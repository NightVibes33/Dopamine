#!/usr/bin/env python3
"""Redacted guard-provenance classification for CAND-001.

Static analysis only. The tool groups aggregate guard-site context into coarse
semantic hypotheses such as state/iteration, bounds-or-size-like validation,
bookkeeping/error-state updates, and loaded-state checks. It deliberately does
not emit function offsets, branch/call targets, operands, constants, USB request
values, crafted inputs, trigger sequences, patches, or exploit instructions.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from collections import Counter
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
CROSS = load_module("crossgen", ROOT / "cand001-crossgen-structure.py")
SEM = load_module("semshape", ROOT / "cand001-semantic-shape.py")

COMPARES = {"cmp", "cmn", "tst", "ccmp", "ccmn"}
ZERO_GUARDS = {"cbz", "cbnz"}
BIT_GUARDS = {"tbz", "tbnz"}
CALLS = {"bl", "blr"}
MOVES = {"mov", "movk", "movn", "movz"}


def mnem(ins) -> str:
    return ins.mnemonic.lower()


def any_prefix(ms, prefixes) -> bool:
    return any(x.startswith(prefixes) for x in ms)


def guard_sites(insns):
    """Return internal, non-serialized guard descriptors.

    Each descriptor contains booleans/counts only. Addresses and branch targets
    are consumed transiently for back-edge classification and never returned by
    build_report().
    """
    ms = [mnem(x) for x in insns]
    n = len(insns)
    out = []

    def context(guard_i: int, compare_i: int | None):
        anchor = compare_i if compare_i is not None else guard_i
        before = ms[max(0, anchor - 3):anchor]
        after = ms[guard_i + 1:min(n, guard_i + 4)]
        target = STRUCT.direct_target(insns[guard_i])
        back_edge = target is not None and target < insns[guard_i].address
        return {
            "arithmetic_before": any_prefix(before, SEM.ARITH_PREFIXES),
            "load_before": any_prefix(before, SEM.LOAD_PREFIXES),
            "store_after": any_prefix(after, SEM.STORE_PREFIXES),
            "call_nearby": any(x in CALLS for x in before + after),
            "move_nearby": any(x in MOVES for x in before + after),
            "back_edge": back_edge,
            "flag_compare": compare_i is not None,
            "zero_test": ms[guard_i] in ZERO_GUARDS,
            "bit_test": ms[guard_i] in BIT_GUARDS,
        }

    consumed = set()
    for i, m in enumerate(ms):
        if m not in COMPARES:
            continue
        for d in range(1, 4):
            j = i + d
            if j >= n:
                break
            if SEM.is_flag_branch(ms[j]):
                if j not in consumed:
                    out.append(context(j, i))
                    consumed.add(j)
                break

    for i, m in enumerate(ms):
        if i in consumed:
            continue
        if m in ZERO_GUARDS or m in BIT_GUARDS:
            out.append(context(i, None))

    return out


def classify(site: dict) -> str:
    # Coarse mutually-exclusive provenance hypotheses. These are deliberately
    # conservative and cannot identify the validated field or attacker input.
    if site["back_edge"]:
        return "state_transition_or_iteration_like"
    if site["arithmetic_before"] and site["load_before"]:
        return "bounds_or_size_validation_like"
    if site["arithmetic_before"] and site["store_after"]:
        return "state_bookkeeping_update_like"
    if site["store_after"]:
        return "bookkeeping_or_error_state_like"
    if site["load_before"]:
        return "loaded_state_validation_like"
    if site["call_nearby"]:
        return "helper_result_validation_like"
    if site["bit_test"] or site["zero_test"]:
        return "compact_flag_or_presence_validation_like"
    return "simple_state_or_flag_validation_like"


def summarize(insns):
    sites = guard_sites(insns)
    cats = Counter(classify(x) for x in sites)
    features = Counter()
    for s in sites:
        for k in (
            "arithmetic_before", "load_before", "store_after", "call_nearby",
            "move_nearby", "back_edge", "flag_compare", "zero_test", "bit_test",
        ):
            if s[k]:
                features[k] += 1
    return {
        "guard_sites": len(sites),
        "provenance_hypotheses": dict(sorted(cats.items())),
        "aggregate_context_features": dict(sorted(features.items())),
    }


def homolog_insns(reference_mnemonics, data: bytes):
    func = CROSS.best_homolog(reference_mnemonics, FP.discover(data))
    return STRUCT.decode(data, int(func["start"]), int(func["insns"]))


def positive_delta(current: dict, baseline: dict):
    keys = sorted(set(current) | set(baseline))
    return {k: current.get(k, 0) - baseline.get(k, 0) for k in keys if current.get(k, 0) - baseline.get(k, 0) > 0}


def build_report(a15_a0: bytes, a15_b0: bytes, triage: dict, a14: bytes, a16: bytes, candidate_id: str):
    row = STRUCT.candidate_row(triage, candidate_id)
    if row.get("a_start") is None or not row.get("a_insns") or row.get("b_start") is None or not row.get("b_insns"):
        raise ValueError("candidate requires paired A15 A0 and B0/B1 views")

    a0 = STRUCT.decode(a15_a0, int(row["a_start"]), int(row["a_insns"]))
    b0 = STRUCT.decode(a15_b0, int(row["b_start"]), int(row["b_insns"]))
    ref = [mnem(x) for x in a0]
    a14_insns = homolog_insns(ref, a14)
    a16_insns = homolog_insns(ref, a16)

    summaries = {
        "A14": summarize(a14_insns),
        "A15_A0": summarize(a0),
        "A15_B0_B1": summarize(b0),
        "A16": summarize(a16_insns),
    }

    category_keys = set()
    feature_keys = set()
    for s in summaries.values():
        category_keys.update(s["provenance_hypotheses"])
        feature_keys.update(s["aggregate_context_features"])

    neighbor_category_max = {
        k: max(
            summaries["A14"]["provenance_hypotheses"].get(k, 0),
            summaries["A15_A0"]["provenance_hypotheses"].get(k, 0),
            summaries["A16"]["provenance_hypotheses"].get(k, 0),
        )
        for k in category_keys
    }
    neighbor_feature_max = {
        k: max(
            summaries["A14"]["aggregate_context_features"].get(k, 0),
            summaries["A15_A0"]["aggregate_context_features"].get(k, 0),
            summaries["A16"]["aggregate_context_features"].get(k, 0),
        )
        for k in feature_keys
    }

    b0_cats = summaries["A15_B0_B1"]["provenance_hypotheses"]
    b0_features = summaries["A15_B0_B1"]["aggregate_context_features"]

    return {
        "candidate_id": candidate_id,
        "analysis_kind": "redacted_guard_provenance_hypothesis",
        "revision_summaries": summaries,
        "B0_B1_positive_category_delta_vs_neighbor_max": positive_delta(b0_cats, neighbor_category_max),
        "B0_B1_positive_context_delta_vs_neighbor_max": positive_delta(b0_features, neighbor_feature_max),
        "interpretation": {
            "scope": "coarse static provenance hypotheses only",
            "vulnerability_status": "NOT_ESTABLISHED",
            "security_fix_status": "NOT_ESTABLISHED",
            "attacker_reachability": "NOT_EVALUATED",
            "validated_field_identity": "NOT_EVALUATED",
        },
        "redactions": [
            "function offsets are not emitted",
            "branch/call targets are not emitted",
            "instruction operands and constants are not emitted",
            "USB request values and validated field identities are not emitted",
            "no crafted input, trigger sequence, patch, or exploit instructions are generated",
        ],
        "limitations": [
            "categories are mnemonic-neighborhood hypotheses rather than decompiled semantics",
            "categories are intentionally coarse and mutually exclusive",
            "compiler transforms can change local motif classification",
            "provenance classification does not establish attacker control, vulnerability, or security-fix intent",
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
        args.a15_a0.read_bytes(), args.a15_b0_b1.read_bytes(),
        json.loads(args.triage.read_text(encoding="utf-8")),
        args.a14.read_bytes(), args.a16.read_bytes(), args.candidate,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
