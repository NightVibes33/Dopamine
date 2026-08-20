#!/usr/bin/env python3
"""Redacted semantic-shape classification for CAND-001 and neighboring homologs.

Static analysis only. The tool classifies aggregate validation/state motifs from
mnemonic/control-flow shape. It deliberately omits addresses, branch/call
targets, operands, crafted inputs, trigger sequences, patches, and exploit
instructions.
"""
from __future__ import annotations

import argparse
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
CROSS = load_module("crossgen", ROOT / "cand001-crossgen-structure.py")

COMPARES = {"cmp", "cmn", "tst", "ccmp", "ccmn"}
ZERO_GUARDS = {"cbz", "cbnz"}
BIT_GUARDS = {"tbz", "tbnz"}
ARITH_PREFIXES = ("add", "sub", "mul", "madd", "msub", "udiv", "sdiv", "adc", "sbc")
LOAD_PREFIXES = ("ldr", "ldp", "ldur", "ldxr", "ldar", "ldtr")
STORE_PREFIXES = ("str", "stp", "stur", "stxr", "stlr", "sttr")


def mnemonic(ins):
    return ins.mnemonic.lower()


def is_flag_branch(m: str) -> bool:
    return m.startswith("b.") and m != "b.al"


def is_arithmetic(m: str) -> bool:
    return m.startswith(ARITH_PREFIXES)


def is_load(m: str) -> bool:
    return m.startswith(LOAD_PREFIXES)


def is_store(m: str) -> bool:
    return m.startswith(STORE_PREFIXES)


def motif_metrics(insns):
    ms = [mnemonic(x) for x in insns]
    n = len(ms)

    flag_compare_guard_pairs = 0
    guard_records = {}

    def mark_guard(idx: int, kind: str, anchor: int):
        rec = guard_records.setdefault(idx, {
            "kind": kind,
            "arithmetic_before": False,
            "load_before": False,
            "store_after": False,
        })
        rec["arithmetic_before"] |= any(is_arithmetic(ms[k]) for k in range(max(0, anchor - 2), anchor))
        rec["load_before"] |= any(is_load(ms[k]) for k in range(max(0, anchor - 2), anchor))
        rec["store_after"] |= any(is_store(ms[k]) for k in range(idx + 1, min(n, idx + 4)))

    for i, m in enumerate(ms):
        if m in COMPARES:
            for d in range(1, 4):
                j = i + d
                if j >= n:
                    break
                if is_flag_branch(ms[j]):
                    flag_compare_guard_pairs += 1
                    mark_guard(j, "flag", i)
                    break
        elif m in ZERO_GUARDS:
            mark_guard(i, "zero", i)
        elif m in BIT_GUARDS:
            mark_guard(i, "bit", i)

    guard_indices = sorted(guard_records)
    clusters = []
    cur = []
    for idx in guard_indices:
        if not cur or idx - cur[-1] <= 3:
            cur.append(idx)
        else:
            clusters.append(cur)
            cur = [idx]
    if cur:
        clusters.append(cur)

    cluster_sizes = [len(c) for c in clusters]
    nested_guard_pressure = sum(max(0, size - 1) for size in cluster_sizes)

    unique_flag_guard_sites = sum(1 for x in guard_records.values() if x["kind"] == "flag")
    zero_test_guard_sites = sum(1 for x in guard_records.values() if x["kind"] == "zero")
    bit_test_guard_sites = sum(1 for x in guard_records.values() if x["kind"] == "bit")
    total_guard_sites = len(guard_records)
    arithmetic_before_guard = sum(1 for x in guard_records.values() if x["arithmetic_before"])
    load_before_guard = sum(1 for x in guard_records.values() if x["load_before"])
    store_after_guard = sum(1 for x in guard_records.values() if x["store_after"])

    cfg = STRUCT.cfg_metrics(insns)
    counts = STRUCT.category_counts(insns)

    if total_guard_sites >= 8 or cfg["compare_guard_pairs"] >= 8:
        semantic_shape = "dense_multi_guard_state_validation"
    elif cfg["back_edge_estimate"] and total_guard_sites >= 3:
        semantic_shape = "guarded_iterative_state_validation"
    elif total_guard_sites >= 3:
        semantic_shape = "compact_guarded_validation"
    elif counts["direct_calls"] >= 3:
        semantic_shape = "helper_orchestrated_validation"
    else:
        semantic_shape = "mixed_validation_helper"

    def density(x):
        return round(x / n, 4) if n else 0.0

    return {
        "instructions": n,
        "guard_motifs": {
            "flag_compare_guard_pairs": flag_compare_guard_pairs,
            "unique_flag_guard_sites": unique_flag_guard_sites,
            "zero_test_guard_sites": zero_test_guard_sites,
            "bit_test_guard_sites": bit_test_guard_sites,
            "total_unique_guard_sites": total_guard_sites,
            "guard_clusters": len(clusters),
            "max_guard_cluster_size": max(cluster_sizes, default=0),
            "nested_guard_pressure": nested_guard_pressure,
        },
        "dataflow_context": {
            "arithmetic_before_guard": arithmetic_before_guard,
            "load_before_guard": load_before_guard,
            "store_after_guard": store_after_guard,
            "arithmetic_before_guard_density": density(arithmetic_before_guard),
            "load_before_guard_density": density(load_before_guard),
            "store_after_guard_density": density(store_after_guard),
        },
        "control_shape": {
            "basic_block_estimate": cfg["basic_block_estimate"],
            "back_edge_estimate": cfg["back_edge_estimate"],
            "compare_guard_pairs": cfg["compare_guard_pairs"],
            "direct_calls": counts["direct_calls"],
        },
        "semantic_shape_hypothesis": semantic_shape,
    }


def pick_homolog(reference_mnemonics, data: bytes):
    funcs = FP.discover(data)
    return CROSS.best_homolog(reference_mnemonics, funcs)


def decode_func(data: bytes, func):
    return STRUCT.decode(data, int(func["start"]), int(func["insns"]))


def build_report(a15_a0: bytes, a15_b0: bytes, triage: dict, a14: bytes, a16: bytes, candidate_id: str):
    row = STRUCT.candidate_row(triage, candidate_id)
    if row.get("a_start") is None or not row.get("a_insns") or row.get("b_start") is None or not row.get("b_insns"):
        raise ValueError("candidate requires paired A15 A0 and B0/B1 views")

    a0_insns = STRUCT.decode(a15_a0, int(row["a_start"]), int(row["a_insns"]))
    b0_insns = STRUCT.decode(a15_b0, int(row["b_start"]), int(row["b_insns"]))
    ref = [mnemonic(x) for x in a0_insns]

    a14_func = pick_homolog(ref, a14)
    a16_func = pick_homolog(ref, a16)

    shapes = {
        "A14": motif_metrics(decode_func(a14, a14_func)),
        "A15_A0": motif_metrics(a0_insns),
        "A15_B0_B1": motif_metrics(b0_insns),
        "A16": motif_metrics(decode_func(a16, a16_func)),
    }

    a0_guards = shapes["A15_A0"]["guard_motifs"]["total_unique_guard_sites"]
    b0_guards = shapes["A15_B0_B1"]["guard_motifs"]["total_unique_guard_sites"]
    a14_guards = shapes["A14"]["guard_motifs"]["total_unique_guard_sites"]
    a16_guards = shapes["A16"]["guard_motifs"]["total_unique_guard_sites"]

    interpretation = {
        "b0_b1_unique_guard_expansion_vs_a0": b0_guards - a0_guards,
        "b0_b1_unique_guard_expansion_vs_neighbor_max": b0_guards - max(a14_guards, a16_guards),
        "b0_b1_semantic_shape": shapes["A15_B0_B1"]["semantic_shape_hypothesis"],
        "a0_semantic_shape": shapes["A15_A0"]["semantic_shape_hypothesis"],
        "b0_b1_unique_dense_guard_shape": (
            shapes["A15_B0_B1"]["semantic_shape_hypothesis"] == "dense_multi_guard_state_validation"
            and all(shapes[x]["semantic_shape_hypothesis"] != "dense_multi_guard_state_validation" for x in ("A14", "A15_A0", "A16"))
        ),
        "measurement_note": "compare→guard pair counts may exceed distinct guard branch sites when multiple compares feed one branch",
        "vulnerability_status": "NOT_ESTABLISHED",
        "security_fix_status": "NOT_ESTABLISHED",
    }

    return {
        "candidate_id": candidate_id,
        "analysis_kind": "redacted_cross_generation_semantic_shape",
        "semantic_shapes": shapes,
        "interpretation": interpretation,
        "redactions": [
            "function offsets are not emitted",
            "branch/call targets are not emitted",
            "instruction operands are not emitted",
            "no constants, USB request values, crafted inputs, or trigger sequences are emitted",
        ],
        "limitations": [
            "motifs are inferred from mnemonic/control-flow shape rather than symbols or decompilation",
            "guard clusters are coarse static estimates",
            "indirect control flow is not resolved",
            "semantic-shape distinctness does not establish a security fix or vulnerability",
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
