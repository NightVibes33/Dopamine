#!/usr/bin/env python3
"""Annotate SecureROM function-triage candidates with segment layout.

Consumes Ibis JSON layout output for both revisions plus the static function
triage report. This is classification only; no binary modification or exploit
construction is performed.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def locate(layout, offset):
    if offset is None:
        return None
    for name, region in layout.get("regions", {}).items():
        start = region.get("offset")
        size = region.get("size")
        if start is None or size is None:
            continue
        if start <= offset < start + size:
            return name
    return "UNMAPPED"


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("base_layout", type=Path)
    ap.add_argument("candidate_layout", type=Path)
    ap.add_argument("triage", type=Path)
    ap.add_argument("--output", type=Path)
    args=ap.parse_args()
    la, lb, tri = load(args.base_layout), load(args.candidate_layout), load(args.triage)
    rows=[]
    for row in tri.get("ranked_candidates", []):
        r=dict(row)
        r["a_segment"] = locate(la, r.get("a_start"))
        r["b_segment"] = locate(lb, r.get("b_start"))
        r["text_relevant"] = r["a_segment"] == "TEXT" or r["b_segment"] == "TEXT"
        rows.append(r)
    text_rows=[r for r in rows if r["text_relevant"]]
    report={
        "base_context":{"app":la.get("app"),"version":la.get("version"),"target":la.get("target"),"regions":la.get("regions")},
        "candidate_context":{"app":lb.get("app"),"version":lb.get("version"),"target":lb.get("target"),"regions":lb.get("regions")},
        "total_triage_candidates":len(rows),
        "text_relevant_candidates":len(text_rows),
        "ranked_text_candidates":text_rows,
        "non_text_candidate_count":len(rows)-len(text_rows),
        "note":"Segment classification narrows static review to executable TEXT. It does not imply vulnerability or exploitability."
    }
    payload=json.dumps(report,indent=2,sort_keys=True)
    print(payload)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(payload+"\n",encoding="utf-8")

if __name__=="__main__":
    main()
