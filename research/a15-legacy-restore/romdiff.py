#!/usr/bin/env python3
"""Offline binary-diff metadata helper for SecureROM research.

This intentionally performs structural comparison only: hashes, sizes, chunk
similarity, changed byte ranges, and printable-string deltas. It does not
construct payloads, patch binaries, or communicate with devices.
"""
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path

PRINTABLE = re.compile(rb"[ -~]{6,}")

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def strings(data: bytes) -> set[str]:
    return {m.group().decode("ascii", "replace") for m in PRINTABLE.finditer(data)}

def changed_ranges(a: bytes, b: bytes):
    n = max(len(a), len(b))
    ranges=[]; start=None
    for i in range(n):
        av = a[i] if i < len(a) else None
        bv = b[i] if i < len(b) else None
        diff = av != bv
        if diff and start is None: start=i
        if not diff and start is not None:
            ranges.append([start, i])
            start=None
    if start is not None: ranges.append([start, n])
    return ranges

def chunk_similarity(a: bytes, b: bytes, chunk: int):
    ah=[hashlib.sha256(a[i:i+chunk]).digest() for i in range(0,len(a),chunk)]
    bh=[hashlib.sha256(b[i:i+chunk]).digest() for i in range(0,len(b),chunk)]
    total=max(len(ah),len(bh))
    same=sum(1 for i in range(min(len(ah),len(bh))) if ah[i]==bh[i])
    return {"chunk_size":chunk,"same_position_chunks":same,"total_positions":total,"ratio":(same/total if total else 1.0)}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("base", type=Path)
    ap.add_argument("candidate", type=Path)
    ap.add_argument("--chunk", type=int, default=4096)
    ap.add_argument("--output", type=Path)
    args=ap.parse_args()
    a=args.base.read_bytes(); b=args.candidate.read_bytes()
    sa, sb = strings(a), strings(b)
    report={
      "base":{"path":str(args.base),"size":len(a),"sha256":sha256(a)},
      "candidate":{"path":str(args.candidate),"size":len(b),"sha256":sha256(b)},
      "chunk_similarity":chunk_similarity(a,b,args.chunk),
      "changed_ranges":changed_ranges(a,b),
      "strings":{"added":sorted(sb-sa),"removed":sorted(sa-sb),"shared_count":len(sa & sb)},
      "note":"Structural diff only; no exploitability conclusion is implied."
    }
    text=json.dumps(report,indent=2)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(text+"\n",encoding="utf-8")

if __name__ == "__main__":
    main()
