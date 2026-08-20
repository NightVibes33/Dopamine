#!/usr/bin/env python3
"""Score static A15 SecureROM research candidates from JSON evidence.

The score prioritizes evidence quality and target relevance. It does not test,
trigger, or operationalize vulnerabilities.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path

WEIGHTS = {
    "retail_relevance": 5,
    "pre_iboot_reachability": 5,
    "external_input": 4,
    "invariant_strength": 4,
    "cross_revision_signal": 3,
    "reproducibility": 4,
    "independent_evidence": 3,
}

GATES = ("retail_relevance", "pre_iboot_reachability")

def validate_level(v):
    if not isinstance(v, int) or v < 0 or v > 3:
        raise ValueError("evidence levels must be integers 0..3")
    return v

def score(record):
    evidence = record.get("evidence", {})
    levels = {k: validate_level(evidence.get(k, 0)) for k in WEIGHTS}
    raw = sum(levels[k] * WEIGHTS[k] for k in WEIGHTS)
    maximum = sum(3 * w for w in WEIGHTS.values())
    gate_ok = all(levels[k] >= 2 for k in GATES)
    if not gate_ok:
        disposition = "HOLD"
    elif raw / maximum >= 0.75:
        disposition = "HIGH_PRIORITY_STATIC_REVIEW"
    elif raw / maximum >= 0.50:
        disposition = "MEDIUM_PRIORITY_STATIC_REVIEW"
    else:
        disposition = "LOW_PRIORITY"
    return {"name": record.get("name"), "score": raw, "max_score": maximum,
            "normalized": round(raw/maximum, 4), "gates_passed": gate_ok,
            "disposition": disposition, "levels": levels}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("candidate", type=Path)
    ap.add_argument("--output", type=Path)
    args=ap.parse_args()
    record=json.loads(args.candidate.read_text(encoding="utf-8"))
    result=score(record)
    text=json.dumps(result, indent=2)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text+"\n", encoding="utf-8")

if __name__ == "__main__":
    main()
