#!/usr/bin/env python3
"""Measure static inlining/refactor signals for an A15 revision candidate.

For one anonymized A15 A0→B0/B1 candidate, this tool decodes direct-call target
bodies and measures whether their normalized mnemonic sequences appear inside
the revised caller body. Output contains aggregate similarities only: no target
addresses, instruction listings, crafted inputs, patches, or device actions.
"""
from __future__ import annotations

import argparse
import difflib
import json
import re
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

TARGET_RE=re.compile(r"#?(0x[0-9a-fA-F]+|[0-9]+)")
RETURNS={"ret","retaa","retab"}
MAX_CALLEE_INSNS=512


def decode_words(data,start,count):
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    out=[]
    for off in range(start,min(len(data),start+count*4),4):
        one=list(md.disasm(data[off:off+4],off,count=1))
        if one: out.append(one[0])
    return out


def target_from_bl(ins):
    if ins.mnemonic.lower()!="bl": return None
    m=TARGET_RE.search(ins.op_str)
    if not m: return None
    try: return int(m.group(1),0)
    except ValueError: return None


def decode_callee(data,start):
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    body=[]
    if start is None or start<0 or start>=len(data): return body
    for off in range(start,min(len(data),start+MAX_CALLEE_INSNS*4),4):
        one=list(md.disasm(data[off:off+4],off,count=1))
        if not one: break
        body.append(one[0])
        if one[0].mnemonic.lower() in RETURNS: break
    return body


def mn(body): return [x.mnemonic.lower() for x in body]


def best_window_similarity(needle,haystack):
    if not needle or not haystack: return 0.0
    n=len(needle); best=0.0
    minw=max(3,int(n*.70)); maxw=min(len(haystack),max(minw,int(n*1.30)+1))
    if len(haystack)<minw:
        return difflib.SequenceMatcher(None,needle,haystack,autojunk=False).ratio()
    for w in range(minw,maxw+1):
        for i in range(0,len(haystack)-w+1):
            s=difflib.SequenceMatcher(None,needle,haystack[i:i+w],autojunk=False).ratio()
            if s>best: best=s
    return best


def call_bodies(data,start,count):
    caller=decode_words(data,start,count)
    bodies=[]
    seen=set()
    for ins in caller:
        target=target_from_bl(ins)
        if target is None or target in seen: continue
        seen.add(target)
        body=decode_callee(data,target)
        if body:
            bodies.append(body)
    return caller,bodies


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("a0",type=Path); ap.add_argument("b0",type=Path); ap.add_argument("triage",type=Path)
    ap.add_argument("--candidate",default="CAND-001")
    ap.add_argument("--output",type=Path)
    args=ap.parse_args()
    a=args.a0.read_bytes(); b=args.b0.read_bytes(); tri=json.loads(args.triage.read_text())
    rows=tri.get("ranked_candidates",[])
    try: index=int(args.candidate.split("-")[-1])-1
    except Exception: raise SystemExit("candidate must use CAND-NNN format")
    if index<0 or index>=len(rows): raise SystemExit("candidate not found")
    row=rows[index]
    if row.get("a_start") is None or row.get("b_start") is None:
        raise SystemExit("candidate requires both A0 and B0/B1 sides")

    acaller, acallees=call_bodies(a,int(row["a_start"]),int(row["a_insns"]))
    bcaller, bcallees=call_bodies(b,int(row["b_start"]),int(row["b_insns"]))
    amn,bmn=mn(acaller),mn(bcaller)

    a_into_b=[]
    for i,body in enumerate(acallees,1):
        seq=mn(body)
        a_into_b.append({"callee_id":f"A0-CALLEE-{i:02d}","callee_insns":len(seq),"best_similarity_inside_B0_B1_caller":round(best_window_similarity(seq,bmn),4)})
    b_into_a=[]
    for i,body in enumerate(bcallees,1):
        seq=mn(body)
        b_into_a.append({"callee_id":f"B0-CALLEE-{i:02d}","callee_insns":len(seq),"best_similarity_inside_A0_caller":round(best_window_similarity(seq,amn),4)})

    strong=sum(x["best_similarity_inside_B0_B1_caller"]>=.80 for x in a_into_b)
    likely=sum(x["best_similarity_inside_B0_B1_caller"]>=.65 for x in a_into_b)
    if acallees and strong>=1:
        disposition="STRONG_STATIC_INLINING_SIGNAL"
    elif acallees and likely>=1:
        disposition="POSSIBLE_STATIC_INLINING_SIGNAL"
    else:
        disposition="NO_CLEAR_STATIC_INLINING_SIGNAL"

    out={
        "candidate_id":args.candidate,
        "A0_caller_insns":len(amn),"B0_B1_caller_insns":len(bmn),
        "A0_direct_call_targets_decoded":len(acallees),"B0_B1_direct_call_targets_decoded":len(bcallees),
        "A0_callee_similarity_inside_B0_B1_caller":a_into_b,
        "B0_B1_callee_similarity_inside_A0_caller":b_into_a,
        "disposition":disposition,
        "note":"Mnemonic-window similarity is a static refactor/inlining signal only; it does not establish semantics, vulnerability, or exploitability."
    }
    text=json.dumps(out,indent=2,sort_keys=True); print(text)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(text+"\n",encoding="utf-8")

if __name__=="__main__": main()
