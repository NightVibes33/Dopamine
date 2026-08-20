#!/usr/bin/env python3
"""Instruction-class differential triage for two ARM64 SecureROM images.

Requires capstone. Produces aggregate static-analysis metadata only: decoded
instruction counts, broad instruction-class deltas, and per-page density. It
never patches or executes the input binaries and does not communicate with a
device.
"""
from __future__ import annotations
import argparse, collections, hashlib, json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

BRANCH = {"b","bl","br","blr","ret","cbz","cbnz","tbz","tbnz"}
SYSTEM_PREFIXES = ("mrs","msr","sys","sysl","isb","dsb","dmb","eret","svc","hvc","smc")
LOAD_PREFIXES = ("ldr","ldp","ldur","ldxr","ldax","prfm")
STORE_PREFIXES = ("str","stp","stur","stxr","stlx")

def classify(mn: str) -> str:
    m=mn.lower()
    if m in BRANCH or m.startswith("b."):
        return "control_flow"
    if m.startswith(SYSTEM_PREFIXES):
        return "system"
    if m.startswith(LOAD_PREFIXES):
        return "load"
    if m.startswith(STORE_PREFIXES):
        return "store"
    if m.startswith(("add","sub","adc","sbc","mul","madd","msub","udiv","sdiv")):
        return "arithmetic"
    if m.startswith(("and","orr","eor","bic","lsl","lsr","asr","ror")):
        return "logic"
    if m.startswith(("cmp","cmn","tst","ccmp","fccmp")):
        return "compare"
    if m.startswith(("mov","adr","adrp")):
        return "move_address"
    return "other"

def decode_word(md, data: bytes, off: int):
    if off+4 > len(data): return None
    ins=list(md.disasm(data[off:off+4], off, count=1))
    return ins[0] if ins else None

def sha256(b: bytes): return hashlib.sha256(b).hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("base", type=Path)
    ap.add_argument("candidate", type=Path)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--page", type=int, default=4096)
    args=ap.parse_args()
    a=args.base.read_bytes(); b=args.candidate.read_bytes()
    md=Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    counts=collections.Counter(); transitions=collections.Counter(); pages=collections.defaultdict(collections.Counter)
    changed_words=0; decoded_pairs=0
    limit=min(len(a),len(b)) & ~3
    for off in range(0,limit,4):
        wa=a[off:off+4]; wb=b[off:off+4]
        if wa==wb: continue
        changed_words += 1
        ia=decode_word(md,a,off); ib=decode_word(md,b,off)
        if ia: counts["base_decoded"] += 1
        if ib: counts["candidate_decoded"] += 1
        if ia and ib:
            decoded_pairs += 1
            ca, cb = classify(ia.mnemonic), classify(ib.mnemonic)
            counts[f"base_{ca}"] += 1; counts[f"candidate_{cb}"] += 1
            transitions[f"{ca}->{cb}"] += 1
            if ia.mnemonic == ib.mnemonic:
                counts["same_mnemonic_changed_encoding"] += 1
            else:
                counts["mnemonic_changed"] += 1
            p=off//args.page
            pages[p]["changed_decoded_pairs"] += 1
            pages[p][f"to_{cb}"] += 1
        else:
            pages[off//args.page]["changed_nonpair"] += 1
    page_rows=[]
    for p,c in pages.items():
        row={"offset_start":p*args.page,"offset_end":(p+1)*args.page,**dict(c)}
        row["score"] = c.get("changed_decoded_pairs",0)+c.get("changed_nonpair",0)
        page_rows.append(row)
    page_rows.sort(key=lambda x:x["score"], reverse=True)
    report={
      "base":{"size":len(a),"sha256":sha256(a)},
      "candidate":{"size":len(b),"sha256":sha256(b)},
      "changed_4byte_words":changed_words,
      "decoded_changed_pairs":decoded_pairs,
      "class_counts":dict(counts),
      "class_transitions":dict(transitions),
      "top_pages":page_rows[:32],
      "note":"Aggregate static instruction triage only; no exploitability is implied."
    }
    text=json.dumps(report,indent=2,sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(text+"\n",encoding="utf-8")

if __name__ == "__main__":
    main()
