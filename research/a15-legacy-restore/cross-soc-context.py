#!/usr/bin/env python3
"""Provide anonymized cross-SoC architecture context for T8110 ROM deltas.

The tool compares each ranked A15 changed-function candidate against heuristic
function fingerprints recovered from neighboring A14/T8101 and A16/T8120
SecureROM images. It emits only candidate IDs and similarity summaries; context
function addresses are intentionally omitted. This is static ancestry/context
analysis, not vulnerability or exploit analysis.
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


def decode_mnemonics(data: bytes, start: int, count: int):
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    out=[]
    for off in range(start,min(len(data),start+count*4),4):
        one=list(md.disasm(data[off:off+4],off,count=1))
        if one:
            out.append(one[0].mnemonic.lower())
    return out


def similarity(a,b):
    return difflib.SequenceMatcher(None,a,b,autojunk=False).ratio()


def persistence_class(score):
    if score >= 0.90: return "strong_homolog_signal"
    if score >= 0.75: return "likely_homolog_signal"
    if score >= 0.60: return "weak_homolog_signal"
    return "no_clear_homolog_signal"


def best_context_match(candidate, funcs):
    n=len(candidate)
    if not candidate:
        return {"best_similarity":0.0,"context_insns":0,"persistence_class":"no_clear_homolog_signal"}
    lo=max(3,int(n*0.60)); hi=max(lo,int(n*1.60)+1)
    pool=[f for f in funcs if lo <= f["insns"] <= hi]
    if not pool:
        pool=funcs
    best_score=-1.0; best=None
    for f in pool:
        s=similarity(candidate,f["mnemonics"])
        if s > best_score:
            best_score=s; best=f
    return {
        "best_similarity":round(max(0.0,best_score),4),
        "context_insns":best["insns"] if best else 0,
        "persistence_class":persistence_class(max(0.0,best_score)),
    }


def overall_context(a14,a16):
    x=a14["best_similarity"]; y=a16["best_similarity"]
    if x >= 0.85 and y >= 0.85:
        return "strong_neighboring_generation_context"
    if x < 0.60 and y < 0.60:
        return "no_clear_neighboring_generation_context"
    if (x >= 0.80) != (y >= 0.80):
        return "asymmetric_generation_context"
    return "partial_neighboring_generation_context"


def build_report(a15_a0,a15_b0,triage,a14,a16):
    a14_funcs=FP.discover(a14); a16_funcs=FP.discover(a16)
    rows=[]
    for index,row in enumerate(triage.get("ranked_candidates",[]) or [],1):
        if row.get("a_start") is not None and row.get("a_insns"):
            mn=decode_mnemonics(a15_a0,int(row["a_start"]),int(row["a_insns"]))
            representative="A0"
        elif row.get("b_start") is not None and row.get("b_insns"):
            mn=decode_mnemonics(a15_b0,int(row["b_start"]),int(row["b_insns"]))
            representative="B0_B1"
        else:
            mn=[]; representative="NONE"
        m14=best_context_match(mn,a14_funcs); m16=best_context_match(mn,a16_funcs)
        rows.append({
            "candidate_id":f"CAND-{index:03d}",
            "source_kind":row.get("kind","unknown"),
            "representative_revision":representative,
            "representative_insns":len(mn),
            "A14_t8101":m14,
            "A16_t8120":m16,
            "context_pattern":overall_context(m14,m16),
            "vulnerability_status":"NOT_ESTABLISHED",
        })
    return {
        "candidate_count":len(rows),
        "context_function_candidates":{"A14_t8101":len(a14_funcs),"A16_t8120":len(a16_funcs)},
        "ranked_candidates":rows,
        "method":"mnemonic-sequence similarity against de-duplicated heuristic neighboring-SoC function candidates",
        "limitations":[
            "cross-SoC similarity is architecture context, not a security finding",
            "compiler/layout and hardware-generation differences can lower similarity for true homologs",
            "heuristic function boundaries are not symbols and can be imperfect",
            "no context function addresses are emitted",
            "a candidate remains NOT_ESTABLISHED until independently validated",
        ],
    }


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("a15_a0",type=Path)
    ap.add_argument("a15_b0",type=Path)
    ap.add_argument("triage",type=Path)
    ap.add_argument("a14",type=Path)
    ap.add_argument("a16",type=Path)
    ap.add_argument("--output",type=Path)
    args=ap.parse_args()
    report=build_report(
        args.a15_a0.read_bytes(),args.a15_b0.read_bytes(),json.loads(args.triage.read_text()),
        args.a14.read_bytes(),args.a16.read_bytes())
    text=json.dumps(report,indent=2,sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(text+"\n",encoding="utf-8")

if __name__=="__main__": main()
