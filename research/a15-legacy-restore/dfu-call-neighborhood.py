#!/usr/bin/env python3
"""Static call-neighborhood comparison for SecureROM DFU descriptor helpers.

The analysis finds functions that resolve the printable DFU descriptor, then
summarizes direct callers/callees around those functions using normalized
mnemonic fingerprints. Output is graph metadata only: no instruction listings,
payloads, patches, crafted USB requests, or device interaction.
"""
from __future__ import annotations

import argparse
import collections
import difflib
import hashlib
import importlib.util
import json
import re
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ROOT=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("dfu_lineage", ROOT/"dfu-lineage.py")
DL=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(DL)

TARGET_RE=re.compile(r"#?(0x[0-9a-fA-F]+|[0-9]+)")


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def file_to_vaddr(layout, off):
    for r in layout.get("regions",{}).values():
        ro=r.get("offset"); sz=r.get("size")
        if ro is not None and sz is not None and ro <= off < ro+sz:
            return r["start"]+(off-ro)
    return None


def vaddr_to_file(layout, addr):
    for r in layout.get("regions",{}).values():
        if r.get("start") is None or r.get("end") is None:
            continue
        if r["start"] <= addr < r["end"] and r.get("offset") is not None:
            return r["offset"]+(addr-r["start"])
    return None


def direct_targets(body, layout):
    out=[]
    for ins in body:
        if ins.mnemonic.lower() != "bl":
            continue
        m=TARGET_RE.search(ins.op_str)
        if not m:
            continue
        try:
            va=int(m.group(1),0)
        except ValueError:
            continue
        fo=vaddr_to_file(layout,va)
        if fo is not None:
            out.append(fo)
    return out


def fingerprint(body):
    mn=[x.mnemonic.lower() for x in body]
    return hashlib.sha256(" ".join(mn).encode()).hexdigest()


def sim_body(a,b):
    ma=[x.mnemonic.lower() for x in a]
    mb=[x.mnemonic.lower() for x in b]
    return difflib.SequenceMatcher(None,ma,mb,autojunk=False).ratio()


def analyze_image(label, rom: Path, layout_path: Path):
    data=rom.read_bytes(); layout=load(layout_path)
    funcs=DL.discover(data,layout)
    by_start={s:body for s,body in funcs}

    descriptor_offsets=[]; pos=0
    while True:
        i=data.find(DL.LABEL,pos)
        if i<0: break
        descriptor_offsets.append(i); pos=i+1
    descriptor_vaddrs={file_to_vaddr(layout,x) for x in descriptor_offsets}

    descriptor_funcs=[]
    for start,body in funcs:
        if set(DL.resolved_targets(body)) & descriptor_vaddrs:
            descriptor_funcs.append((start,body))

    callers=collections.defaultdict(list)
    callees={}
    for start,body in funcs:
        targets=direct_targets(body,layout)
        callees[start]=targets
        for target in targets:
            callers[target].append(start)

    def node_summary(start,body):
        direct=callees.get(start,[])
        internal=[t for t in direct if t in by_start]
        callee_fps=sorted({fingerprint(by_start[t]) for t in internal})
        incoming=callers.get(start,[])
        caller_fps=sorted({fingerprint(by_start[t]) for t in incoming if t in by_start})
        sizes=collections.Counter(len(by_start[t]) for t in internal)
        return {
            "insns":len(body),
            "fingerprint":fingerprint(body),
            "direct_call_count":len(direct),
            "internal_direct_call_count":len(internal),
            "unique_internal_callee_fingerprints":len(callee_fps),
            "incoming_caller_count":len(incoming),
            "unique_incoming_caller_fingerprints":len(caller_fps),
            "callee_instruction_size_histogram":dict(sorted(sizes.items())),
            "callee_fingerprints":callee_fps,
            "caller_fingerprints":caller_fps,
        }

    descriptors=[]
    for start,body in descriptor_funcs:
        item=node_summary(start,body)
        item["role"]="descriptor_helper" if len(body)<=8 else "descriptor_logic"
        descriptors.append((start,body,item))

    # The tiny descriptor helper is especially useful when larger logic stops
    # directly referencing the string. Summarize all direct callers to it.
    helper_callers=[]
    for start,body,item in descriptors:
        if item["role"] != "descriptor_helper":
            continue
        for caller_start in callers.get(start,[]):
            caller_body=by_start.get(caller_start)
            if not caller_body:
                continue
            summary=node_summary(caller_start,caller_body)
            summary["descriptor_helper_fingerprint"]=item["fingerprint"]
            helper_callers.append((caller_start,caller_body,summary))

    # De-duplicate callers by fingerprint + length for concise metadata.
    dedup={}
    for start,body,item in helper_callers:
        dedup[(item["fingerprint"],item["insns"])]=(start,body,item)
    helper_callers=list(dedup.values())

    return {
        "label":label,
        "layout":{"app":layout.get("app"),"target":layout.get("target"),"version":layout.get("version")},
        "descriptor_function_count":len(descriptors),
        "descriptor_functions":[item for _,_,item in descriptors],
        "descriptor_helper_caller_count":len(helper_callers),
        "descriptor_helper_callers":[item for _,_,item in helper_callers],
        "_descriptor_bodies":[body for _,body,_ in descriptors],
        "_caller_bodies":[body for _,body,_ in helper_callers],
    }


def best_similarity(a_bodies,b_bodies):
    rows=[]
    for a in a_bodies:
        for b in b_bodies:
            rows.append({"a_insns":len(a),"b_insns":len(b),"mnemonic_similarity":round(sim_body(a,b),4)})
    rows.sort(key=lambda x:x["mnemonic_similarity"],reverse=True)
    return rows[:12]


def clean(image):
    return {k:v for k,v in image.items() if not k.startswith("_")}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--image",action="append",nargs=3,metavar=("LABEL","ROM","LAYOUT"),required=True)
    ap.add_argument("--output",type=Path)
    args=ap.parse_args()

    images=[analyze_image(label,Path(rom),Path(layout)) for label,rom,layout in args.image]
    comparisons=[]
    for i in range(len(images)):
        for j in range(i+1,len(images)):
            a,b=images[i],images[j]
            comparisons.append({
                "a":a["label"],"b":b["label"],
                "descriptor_function_best_matches":best_similarity(a["_descriptor_bodies"],b["_descriptor_bodies"]),
                "descriptor_helper_caller_best_matches":best_similarity(a["_caller_bodies"],b["_caller_bodies"]),
            })

    out={
        "descriptor":DL.LABEL.decode(),
        "images":[clean(x) for x in images],
        "comparisons":comparisons,
        "method":"direct-BL static call-neighborhood around descriptor-resolving functions; mnemonic fingerprints only",
        "note":"Graph similarity is lineage/topology evidence only and does not establish vulnerability or exploitability."
    }
    text=json.dumps(out,indent=2,sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(text+"\n",encoding="utf-8")

if __name__=="__main__":
    main()
