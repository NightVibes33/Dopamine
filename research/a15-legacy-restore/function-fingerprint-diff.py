#!/usr/bin/env python3
"""Heuristic ARM64 function fingerprint diff for SecureROM revisions.

Static triage only. The tool scans every aligned word, seeds likely function
starts from common prologues and direct BL targets, then compares normalized
mnemonic sequences. It does not patch or execute the binaries.
"""
from __future__ import annotations
import argparse, collections, difflib, hashlib, json, re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

MAX_INSNS = 2048
MIN_INSNS = 3
TARGET_RE = re.compile(r"#?(0x[0-9a-fA-F]+|[0-9]+)")


def is_start(window):
    if not window or any(x is None for x in window):
        return False
    m=[x.mnemonic.lower() for x in window]
    o=[x.op_str.lower() for x in window]
    if m[0] in ("paciasp","pacibsp"):
        return len(m)>1 and (m[1]=="stp" or (m[1]=="sub" and "sp" in o[1]))
    if m[0]=="stp" and "x29" in o[0] and "x30" in o[0] and "sp" in o[0]:
        return True
    if m[0]=="sub" and o[0].startswith("sp, sp"):
        return len(m)>1 and (m[1]=="stp" or m[1] in ("mov","add"))
    return False


def is_end(ins):
    return ins.mnemonic.lower() in ("ret","retaa","retab")


def decode_map(data: bytes):
    md=Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out={}
    for off in range(0, len(data)-3, 4):
        one=list(md.disasm(data[off:off+4], off, count=1))
        if one:
            out[off]=one[0]
    return out


def branch_target(ins):
    if ins.mnemonic.lower() != "bl":
        return None
    match=TARGET_RE.search(ins.op_str)
    if not match:
        return None
    try:
        return int(match.group(1), 0)
    except ValueError:
        return None


def overlap_ratio(a, b):
    lo=max(a["start"], b["start"])
    hi=min(a["end"], b["end"])
    if hi <= lo:
        return 0.0
    inter=hi-lo
    shorter=min(a["end"]-a["start"], b["end"]-b["start"])
    return inter/shorter if shorter else 0.0


def dedupe_functions(funcs):
    """Collapse near-identical heuristic boundaries without inventing functions."""
    kept=[]
    for f in sorted(funcs, key=lambda x:(x["end"], x["start"])):
        duplicate=None
        for k in reversed(kept):
            if k["end"] != f["end"]:
                if k["end"] < f["end"]:
                    break
                continue
            if abs(k["start"]-f["start"]) <= 16 and overlap_ratio(k, f) >= 0.90:
                duplicate=k
                break
        if duplicate is None:
            kept.append(dict(f))
            continue
        merged_sources=sorted(set(duplicate["sources"]) | set(f["sources"]))
        def rank(x):
            return ("bl_target" in x["sources"], x["end"]-x["start"], -x["start"])
        if rank(f) > rank(duplicate):
            replacement=dict(f)
            replacement["sources"]=merged_sources
            kept[kept.index(duplicate)]=replacement
        else:
            duplicate["sources"]=merged_sources
    return sorted(kept, key=lambda x:x["start"])


def discover(data: bytes):
    by_addr=decode_map(data)
    starts=collections.defaultdict(set)
    for off, ins in by_addr.items():
        win=[by_addr.get(off),by_addr.get(off+4),by_addr.get(off+8)]
        if is_start(win):
            starts[off].add("prologue")
        target=branch_target(ins)
        if target is not None and target in by_addr and target % 4 == 0:
            starts[target].add("bl_target")

    funcs=[]
    start_set=set(starts)
    for start in sorted(start_set):
        body=[]; addr=start
        for index in range(MAX_INSNS):
            cur=by_addr.get(addr)
            if cur is None:
                break
            if index >= MIN_INSNS and addr in start_set and addr != start:
                break
            body.append(cur)
            addr += 4
            if is_end(cur):
                break
        if len(body)>=MIN_INSNS and is_end(body[-1]):
            mn=[x.mnemonic.lower() for x in body]
            funcs.append({
                "start":start,
                "end":body[-1].address+4,
                "insns":len(body),
                "sources":sorted(starts[start]),
                "mnemonics":mn,
                "fingerprint":hashlib.sha256(" ".join(mn).encode()).hexdigest(),
            })
    return dedupe_functions(funcs)


def similarity(a,b):
    return difflib.SequenceMatcher(None,a["mnemonics"],b["mnemonics"],autojunk=False).ratio()


def compare(a_funcs,b_funcs):
    b_by_fp=collections.defaultdict(list)
    for f in b_funcs:
        b_by_fp[f["fingerprint"]].append(f)
    exact=[]; unmatched_a=[]; used_b=set()
    for a in a_funcs:
        pick=next((x for x in b_by_fp.get(a["fingerprint"],[]) if x["start"] not in used_b),None)
        if pick:
            exact.append({"a_start":a["start"],"b_start":pick["start"],"insns":a["insns"]})
            used_b.add(pick["start"])
        else:
            unmatched_a.append(a)
    unmatched_b=[b for b in b_funcs if b["start"] not in used_b]

    buckets=collections.defaultdict(list)
    for b in unmatched_b:
        buckets[b["insns"]//8].append(b)
    similar=[]; consumed=set()
    for a in sorted(unmatched_a,key=lambda x:x["insns"],reverse=True):
        bucket=a["insns"]//8
        pool=[]
        for k in range(max(0,bucket-5),bucket+6):
            pool.extend(x for x in buckets.get(k,[]) if x["start"] not in consumed)
        candidates=[]
        for b in pool:
            ratio=b["insns"]/a["insns"] if a["insns"] else 0
            if 0.65 <= ratio <= 1.55:
                s=similarity(a,b)
                if s>=0.55:
                    candidates.append((s,b))
        if candidates:
            s,b=max(candidates,key=lambda x:x[0])
            consumed.add(b["start"])
            similar.append({
                "a_start":a["start"],"b_start":b["start"],
                "a_insns":a["insns"],"b_insns":b["insns"],
                "a_sources":a["sources"],"b_sources":b["sources"],
                "mnemonic_similarity":round(s,4),
            })
    matched_a={x["a_start"] for x in similar}
    remaining_a=[a for a in unmatched_a if a["start"] not in matched_a]
    remaining_b=[b for b in unmatched_b if b["start"] not in consumed]
    return exact,similar,remaining_a,remaining_b


def clean_func(f):
    return {k:v for k,v in f.items() if k != "mnemonics"}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("base",type=Path)
    ap.add_argument("candidate",type=Path)
    ap.add_argument("--output",type=Path)
    args=ap.parse_args()
    a=discover(args.base.read_bytes()); b=discover(args.candidate.read_bytes())
    exact,similar,only_a,only_b=compare(a,b)
    similar_sorted=sorted(similar,key=lambda x:x["mnemonic_similarity"])
    report={
        "heuristic":"aligned ARM64 decode; prologue + direct-BL target starts; return-bounded mnemonic fingerprints; overlapping-boundary de-duplication",
        "base_function_candidates":len(a),
        "candidate_function_candidates":len(b),
        "exact_fingerprint_matches":len(exact),
        "similar_function_matches":len(similar),
        "base_unmatched":len(only_a),
        "candidate_unmatched":len(only_b),
        "lowest_similarity_matches":similar_sorted[:64],
        "base_unmatched_functions":[clean_func(x) for x in only_a[:64]],
        "candidate_unmatched_functions":[clean_func(x) for x in only_b[:64]],
        "note":"Heuristic boundaries are triage hints only; confirm in a segment-aware disassembler before drawing conclusions."
    }
    text=json.dumps(report,indent=2,sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(text+"\n",encoding="utf-8")

if __name__ == "__main__":
    main()
