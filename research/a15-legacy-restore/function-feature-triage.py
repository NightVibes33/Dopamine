#!/usr/bin/env python3
"""Aggregate feature triage for changed SecureROM function candidates.

Consumes the heuristic fingerprint report plus the two ROM revisions and emits
only function-level counts/deltas (control flow, memory ops, arithmetic, etc.).
No payloads, patches, or execution behavior are produced.
"""
from __future__ import annotations
import argparse, collections, json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

BRANCH={"b","bl","br","blr","ret","retaa","retab","cbz","cbnz","tbz","tbnz"}

def category(m):
    m=m.lower()
    if m in BRANCH or m.startswith("b."): return "control_flow"
    if m.startswith(("ldr","ldp","ldur","ldxr","ldax","prfm")): return "load"
    if m.startswith(("str","stp","stur","stxr","stlx")): return "store"
    if m.startswith(("cmp","cmn","tst","ccmp","fccmp")): return "compare"
    if m.startswith(("add","sub","adc","sbc","mul","madd","msub","udiv","sdiv")): return "arithmetic"
    if m.startswith(("and","orr","eor","bic","lsl","lsr","asr","ror")): return "logic"
    if m.startswith(("mrs","msr","sys","sysl","isb","dsb","dmb","eret","svc","hvc","smc")): return "system"
    return "other"

def decode_n(data,start,n):
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    out=[]
    for off in range(start,min(len(data),start+n*4),4):
        one=list(md.disasm(data[off:off+4],off,count=1))
        if one: out.append(one[0])
    return out

def features(data,start,n):
    ins=decode_n(data,start,n)
    c=collections.Counter(category(x.mnemonic) for x in ins)
    c["decoded"] = len(ins)
    c["direct_calls"] = sum(1 for x in ins if x.mnemonic.lower()=="bl")
    c["indirect_calls"] = sum(1 for x in ins if x.mnemonic.lower()=="blr")
    c["indirect_branches"] = sum(1 for x in ins if x.mnemonic.lower()=="br")
    c["conditional_branches"] = sum(1 for x in ins if x.mnemonic.lower() in ("cbz","cbnz","tbz","tbnz") or x.mnemonic.lower().startswith("b."))
    return dict(c)

def delta(a,b):
    keys=set(a)|set(b)
    return {k:b.get(k,0)-a.get(k,0) for k in sorted(keys) if b.get(k,0)!=a.get(k,0)}

def score(pair):
    d=pair.get("delta",{})
    return abs(pair.get("b_insns",0)-pair.get("a_insns",0))*2 + sum(abs(v) for v in d.values())

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("base",type=Path); ap.add_argument("candidate",type=Path)
    ap.add_argument("fingerprints",type=Path); ap.add_argument("--output",type=Path)
    args=ap.parse_args()
    a=args.base.read_bytes(); b=args.candidate.read_bytes(); fp=json.loads(args.fingerprints.read_text())
    rows=[]
    for m in fp.get("lowest_similarity_matches",[]):
        fa=features(a,m["a_start"],m["a_insns"]); fb=features(b,m["b_start"],m["b_insns"])
        row={"kind":"similar_changed","a_start":m["a_start"],"b_start":m["b_start"],"a_insns":m["a_insns"],"b_insns":m["b_insns"],"similarity":m["mnemonic_similarity"],"a_features":fa,"b_features":fb,"delta":delta(fa,fb)}
        row["priority_score"]=score(row); rows.append(row)
    only_a=fp.get("base_unmatched_functions",[]); only_b=fp.get("candidate_unmatched_functions",[])
    used=set()
    for x in only_a:
        near=[y for y in only_b if y["start"] not in used and abs(y["start"]-x["start"])<=0x100]
        if near:
            y=min(near,key=lambda z:abs(z["start"]-x["start"])); used.add(y["start"])
            fa=features(a,x["start"],x["insns"]); fb=features(b,y["start"],y["insns"])
            row={"kind":"nearby_unmatched_pair","a_start":x["start"],"b_start":y["start"],"a_insns":x["insns"],"b_insns":y["insns"],"a_features":fa,"b_features":fb,"delta":delta(fa,fb)}
            row["priority_score"]=score(row); rows.append(row)
        else:
            fa=features(a,x["start"],x["insns"]); rows.append({"kind":"base_only","a_start":x["start"],"a_insns":x["insns"],"a_features":fa,"priority_score":x["insns"]})
    for y in only_b:
        if y["start"] in used: continue
        fb=features(b,y["start"],y["insns"]); rows.append({"kind":"candidate_only","b_start":y["start"],"b_insns":y["insns"],"b_features":fb,"priority_score":y["insns"]})
    rows.sort(key=lambda x:x["priority_score"],reverse=True)
    report={"candidate_count":len(rows),"ranked_candidates":rows,"note":"Feature deltas are static triage signals only and do not establish vulnerability or exploitability."}
    text=json.dumps(report,indent=2,sort_keys=True); print(text)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(text+"\n",encoding="utf-8")

if __name__=="__main__": main()
