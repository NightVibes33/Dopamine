#!/usr/bin/env python3
"""Heuristic ARM64 function fingerprint diff for SecureROM revisions.

This is static triage only. It heuristically discovers likely function bodies,
normalizes mnemonic sequences, and compares revisions to separate layout churn
from likely semantic changes. It does not patch or execute the binaries.
"""
from __future__ import annotations
import argparse, collections, difflib, hashlib, json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

MAX_INSNS = 2048
MIN_INSNS = 4


def is_start(window):
    """Conservative common ARM64/arm64e prologue heuristics."""
    m=[x.mnemonic.lower() for x in window]
    o=[x.op_str.lower() for x in window]
    if not m: return False
    if m[0] in ("paciasp","pacibsp"):
        return len(m)>1 and (m[1]=="stp" or (m[1]=="sub" and "sp" in o[1]))
    if m[0]=="stp" and "x29" in o[0] and "x30" in o[0] and "sp" in o[0]:
        return True
    if m[0]=="sub" and o[0].startswith("sp, sp"):
        return len(m)>1 and (m[1]=="stp" or m[1] in ("mov","add"))
    return False


def is_end(ins):
    return ins.mnemonic.lower() in ("ret","retaa","retab")


def decode_all(data: bytes):
    md=Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    return list(md.disasm(data,0))


def discover(data: bytes):
    ins=decode_all(data)
    by_addr={x.address:x for x in ins}
    starts=[]
    for i in range(len(ins)-2):
        if is_start(ins[i:i+3]): starts.append(ins[i].address)
    funcs=[]
    seen=set()
    for start in starts:
        if start in seen: continue
        body=[]; addr=start
        for _ in range(MAX_INSNS):
            cur=by_addr.get(addr)
            if cur is None: break
            body.append(cur)
            addr += 4
            if is_end(cur): break
        if len(body)>=MIN_INSNS and is_end(body[-1]):
            seen.add(start)
            mn=[x.mnemonic.lower() for x in body]
            classes=collections.Counter(mn)
            funcs.append({
                "start":start,
                "end":body[-1].address+4,
                "insns":len(body),
                "mnemonics":mn,
                "fingerprint":hashlib.sha256(" ".join(mn).encode()).hexdigest(),
                "mnemonic_histogram":dict(classes),
            })
    return funcs


def similarity(a,b):
    return difflib.SequenceMatcher(None,a["mnemonics"],b["mnemonics"],autojunk=False).ratio()


def compare(a_funcs,b_funcs):
    b_by_fp=collections.defaultdict(list)
    for f in b_funcs: b_by_fp[f["fingerprint"]].append(f)
    exact=[]; unmatched_a=[]; used_b=set()
    for a in a_funcs:
        options=b_by_fp.get(a["fingerprint"],[])
        pick=next((x for x in options if x["start"] not in used_b),None)
        if pick:
            exact.append({"a_start":a["start"],"b_start":pick["start"],"insns":a["insns"]})
            used_b.add(pick["start"])
        else:
            unmatched_a.append(a)
    unmatched_b=[b for b in b_funcs if b["start"] not in used_b]
    similar=[]; remaining_b={b["start"]:b for b in unmatched_b}
    for a in sorted(unmatched_a,key=lambda x:x["insns"],reverse=True):
        candidates=[]
        for b in remaining_b.values():
            ratio=b["insns"]/a["insns"] if a["insns"] else 0
            if 0.65 <= ratio <= 1.55:
                s=similarity(a,b)
                if s>=0.55: candidates.append((s,b))
        if candidates:
            s,b=max(candidates,key=lambda x:x[0])
            similar.append({
                "a_start":a["start"],"b_start":b["start"],
                "a_insns":a["insns"],"b_insns":b["insns"],
                "mnemonic_similarity":round(s,4),
            })
            remaining_b.pop(b["start"],None)
    matched_a={x["a_start"] for x in similar}
    remaining_a=[a for a in unmatched_a if a["start"] not in matched_a]
    return exact,similar,remaining_a,list(remaining_b.values())


def clean_func(f):
    return {k:v for k,v in f.items() if k not in ("mnemonics","mnemonic_histogram")}


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
        "heuristic":"common ARM64/arm64e prologue + return bounded mnemonic fingerprinting",
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
