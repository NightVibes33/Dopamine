#!/usr/bin/env python3
"""Compare both sides of each A15 revision candidate to A14/A16 context.

Unlike cross-soc-context.py, this keeps the A15 A0 and B0/B1 sides separate so
an intra-A15 rewrite can be tested independently for neighboring-generation
homologs. Output is anonymized similarity metadata only; no context addresses,
instruction listings, payloads, or device interaction are emitted.
"""
from __future__ import annotations
import argparse, difflib, importlib.util, json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ROOT=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("fpdiff",ROOT/"function-fingerprint-diff.py")
FP=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(FP)


def decode(data,start,count):
    if start is None or not count:
        return []
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    out=[]
    for off in range(int(start),min(len(data),int(start)+int(count)*4),4):
        one=list(md.disasm(data[off:off+4],off,count=1))
        if one: out.append(one[0].mnemonic.lower())
    return out


def similarity(a,b):
    return difflib.SequenceMatcher(None,a,b,autojunk=False).ratio()


def best(mn,funcs):
    if not mn:
        return {"best_similarity":None,"context_insns":None,"class":"not_available"}
    n=len(mn); lo=max(3,int(n*.55)); hi=max(lo,int(n*1.70)+1)
    pool=[f for f in funcs if lo <= f["insns"] <= hi] or funcs
    score=-1.0; picked=None
    for f in pool:
        s=similarity(mn,f["mnemonics"])
        if s>score: score=s; picked=f
    if score>=.90: cls="strong_homolog_signal"
    elif score>=.75: cls="likely_homolog_signal"
    elif score>=.60: cls="weak_homolog_signal"
    else: cls="no_clear_homolog_signal"
    return {"best_similarity":round(max(score,0.0),4),"context_insns":picked["insns"] if picked else None,"class":cls}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("a15_a0",type=Path); ap.add_argument("a15_b0",type=Path)
    ap.add_argument("triage",type=Path); ap.add_argument("a14",type=Path); ap.add_argument("a16",type=Path)
    ap.add_argument("--output",type=Path)
    args=ap.parse_args()
    a=args.a15_a0.read_bytes(); b=args.a15_b0.read_bytes(); tri=json.loads(args.triage.read_text())
    f14=FP.discover(args.a14.read_bytes()); f16=FP.discover(args.a16.read_bytes())
    rows=[]
    for index,row in enumerate(tri.get("ranked_candidates",[]),1):
        am=decode(a,row.get("a_start"),row.get("a_insns")); bm=decode(b,row.get("b_start"),row.get("b_insns"))
        rows.append({
            "candidate_id":f"CAND-{index:03d}",
            "source_kind":row.get("kind"),
            "A0_insns":len(am) if am else None,
            "B0_B1_insns":len(bm) if bm else None,
            "A0_vs_A14":best(am,f14),
            "A0_vs_A16":best(am,f16),
            "B0_B1_vs_A14":best(bm,f14),
            "B0_B1_vs_A16":best(bm,f16),
            "vulnerability_status":"NOT_ESTABLISHED",
        })
    report={
        "candidate_count":len(rows),
        "ranked_candidates":rows,
        "method":"separate A15 A0 and B0/B1 mnemonic-sequence similarity against A14/T8101 and A16/T8120 heuristic functions",
        "note":"Similarity is ancestry/context evidence only and does not establish function identity, vulnerability, or exploitability."
    }
    text=json.dumps(report,indent=2,sort_keys=True); print(text)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(text+"\n",encoding="utf-8")

if __name__=="__main__": main()
