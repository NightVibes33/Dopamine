#!/usr/bin/env python3
"""Compare anonymized aggregate structure of CAND-001 with A14/A16 homologs.

Static research only. The tool finds the strongest mnemonic-shape homologs of the
A15 A0 form in pinned neighboring SecureROM images, then emits aggregate
CFG/data-flow metrics and similarities. It deliberately omits all function
addresses, branch/call targets, operands, crafted inputs, and exploit steps.
"""
from __future__ import annotations

import argparse
import difflib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FP = load_module("fpdiff", ROOT / "function-fingerprint-diff.py")
STRUCT = load_module("candstruct", ROOT / "cand001-static-structure.py")


def mnemonic_similarity(a, b) -> float:
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def best_homolog(reference_mnemonics, funcs):
    n = len(reference_mnemonics)
    if not n:
        raise ValueError("empty A15 reference mnemonic sequence")
    lo = max(3, int(n * 0.60))
    hi = max(lo, int(n * 1.60) + 1)
    pool = [f for f in funcs if lo <= f["insns"] <= hi] or funcs
    if not pool:
        raise ValueError("no neighboring-generation function candidates")
    return max(pool, key=lambda f: mnemonic_similarity(reference_mnemonics, f["mnemonics"]))


def sanitized_metrics(data: bytes, func):
    insns = STRUCT.decode(data, int(func["start"]), int(func["insns"]))
    return STRUCT.characterize(insns)


def compact_delta(base, other):
    return STRUCT.delta(base, other)


def build_report(a15_a0: bytes, a15_b0: bytes, triage: dict, a14: bytes, a16: bytes, candidate_id: str):
    row = STRUCT.candidate_row(triage, candidate_id)
    if row.get("a_start") is None or not row.get("a_insns") or row.get("b_start") is None or not row.get("b_insns"):
        raise ValueError("candidate requires paired A15 A0 and B0/B1 views")

    a0_insns = STRUCT.decode(a15_a0, int(row["a_start"]), int(row["a_insns"]))
    b0_insns = STRUCT.decode(a15_b0, int(row["b_start"]), int(row["b_insns"]))
    reference_mnemonics = [x.mnemonic.lower() for x in a0_insns]

    a14_funcs = FP.discover(a14)
    a16_funcs = FP.discover(a16)
    a14_best = best_homolog(reference_mnemonics, a14_funcs)
    a16_best = best_homolog(reference_mnemonics, a16_funcs)

    a15_a0_metrics = STRUCT.characterize(a0_insns)
    a15_b0_metrics = STRUCT.characterize(b0_insns)
    a14_metrics = sanitized_metrics(a14, a14_best)
    a16_metrics = sanitized_metrics(a16, a16_best)

    a14_similarity = round(mnemonic_similarity(reference_mnemonics, a14_best["mnemonics"]), 4)
    a16_similarity = round(mnemonic_similarity(reference_mnemonics, a16_best["mnemonics"]), 4)

    # Structural-distance score is intentionally coarse and aggregate-only.
    keys = ["basic_block_estimate", "back_edge_estimate", "compare_guard_pairs", "internal_direct_branch_targets"]
    def distance(x, y):
        return sum(abs(x["cfg"][k] - y["cfg"][k]) for k in keys)

    distances = {
        "A15_A0_to_A14": distance(a15_a0_metrics, a14_metrics),
        "A15_A0_to_A16": distance(a15_a0_metrics, a16_metrics),
        "A15_B0_B1_to_A14": distance(a15_b0_metrics, a14_metrics),
        "A15_B0_B1_to_A16": distance(a15_b0_metrics, a16_metrics),
    }

    b0_unique = (
        distances["A15_B0_B1_to_A14"] > distances["A15_A0_to_A14"]
        and distances["A15_B0_B1_to_A16"] > distances["A15_A0_to_A16"]
    )

    return {
        "candidate_id": candidate_id,
        "analysis_kind": "aggregate_cross_generation_cfg_dataflow_context",
        "mnemonic_homolog_similarity": {
            "A14_vs_A15_A0": a14_similarity,
            "A16_vs_A15_A0": a16_similarity,
        },
        "aggregate_structure": {
            "A14": a14_metrics,
            "A15_A0": a15_a0_metrics,
            "A15_B0_B1": a15_b0_metrics,
            "A16": a16_metrics,
        },
        "aggregate_cfg_distance": distances,
        "interpretation": {
            "b0_b1_more_structurally_distinct_from_both_neighbors_than_a0": b0_unique,
            "vulnerability_status": "NOT_ESTABLISHED",
            "security_fix_status": "NOT_ESTABLISHED",
            "note": "structural distinctness is revision-history evidence only and does not establish a security fix",
        },
        "redactions": [
            "function offsets are not emitted",
            "branch/call targets are not emitted",
            "instruction operands are not emitted",
            "no crafted input or trigger sequence is generated",
        ],
        "limitations": [
            "homolog selection uses heuristic mnemonic similarity rather than symbols",
            "aggregate CFG metrics omit indirect control-flow resolution",
            "compiler and layout changes can affect structural similarity",
            "static structure does not establish attacker reachability or exploitability",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("a15_a0", type=Path)
    ap.add_argument("a15_b0_b1", type=Path)
    ap.add_argument("triage", type=Path)
    ap.add_argument("a14", type=Path)
    ap.add_argument("a16", type=Path)
    ap.add_argument("--candidate", default="CAND-001")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    report = build_report(
        args.a15_a0.read_bytes(),
        args.a15_b0_b1.read_bytes(),
        json.loads(args.triage.read_text(encoding="utf-8")),
        args.a14.read_bytes(),
        args.a16.read_bytes(),
        args.candidate,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
