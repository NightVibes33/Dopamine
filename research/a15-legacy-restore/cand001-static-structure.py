#!/usr/bin/env python3
"""Aggregate CFG/data-flow characterization for an anonymized SecureROM candidate.

Static analysis only. Candidate offsets are consumed internally from the existing
triage JSON but are deliberately not emitted. The report contains aggregate
counts/densities and broad structural hypotheses only; it does not produce
branch targets, instruction operands, trigger sequences, patches, or exploit
steps.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

TARGET_RE = re.compile(r"#?(0x[0-9a-fA-F]+|[0-9]+)$")
COMPARES = {"cmp", "cmn", "tst", "ccmp", "ccmn"}
RETURNS = {"ret", "retaa", "retab"}
CALLS = {"bl", "blr"}
INDIRECT_BRANCHES = {"br"}
BIT_TEST_BRANCHES = {"tbz", "tbnz", "cbz", "cbnz"}


def is_cond_branch(mnemonic: str) -> bool:
    m = mnemonic.lower()
    return m in BIT_TEST_BRANCHES or (m.startswith("b.") and m not in {"b.al"})


def is_uncond_branch(mnemonic: str) -> bool:
    return mnemonic.lower() in {"b", "br"}


def direct_target(ins):
    m = ins.mnemonic.lower()
    if not (m == "b" or m == "bl" or is_cond_branch(m)):
        return None
    last = ins.op_str.split(",")[-1].strip()
    match = TARGET_RE.search(last)
    if not match:
        return None
    try:
        return int(match.group(1), 0)
    except ValueError:
        return None


def decode(data: bytes, start: int, insn_count: int):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    end = min(len(data), start + max(0, insn_count) * 4)
    return list(md.disasm(data[start:end], start))


def category_counts(insns):
    out = {
        "instructions": len(insns),
        "compares": 0,
        "conditional_branches": 0,
        "unconditional_branches": 0,
        "direct_calls": 0,
        "indirect_calls": 0,
        "returns": 0,
        "loads": 0,
        "stores": 0,
        "arithmetic": 0,
        "logical_bit_ops": 0,
        "moves": 0,
        "conditional_selects": 0,
    }
    arithmetic_prefixes = ("add", "sub", "mul", "madd", "msub", "udiv", "sdiv", "adc", "sbc")
    logical_prefixes = ("and", "orr", "eor", "bic", "lsl", "lsr", "asr", "ror", "ubf", "sbf")
    load_prefixes = ("ldr", "ldp", "ldur", "ldxr", "ldar", "ldtr")
    store_prefixes = ("str", "stp", "stur", "stxr", "stlr", "sttr")
    for ins in insns:
        m = ins.mnemonic.lower()
        if m in COMPARES:
            out["compares"] += 1
        if is_cond_branch(m):
            out["conditional_branches"] += 1
        elif is_uncond_branch(m):
            out["unconditional_branches"] += 1
        if m == "bl":
            out["direct_calls"] += 1
        elif m == "blr":
            out["indirect_calls"] += 1
        if m in RETURNS:
            out["returns"] += 1
        if m.startswith(load_prefixes):
            out["loads"] += 1
        if m.startswith(store_prefixes):
            out["stores"] += 1
        if m.startswith(arithmetic_prefixes):
            out["arithmetic"] += 1
        if m.startswith(logical_prefixes):
            out["logical_bit_ops"] += 1
        if m in {"mov", "movk", "movn", "movz"}:
            out["moves"] += 1
        if m.startswith(("csel", "csinc", "csinv", "csneg")):
            out["conditional_selects"] += 1
    return out


def cfg_metrics(insns):
    if not insns:
        return {
            "basic_block_estimate": 0,
            "internal_direct_branch_targets": 0,
            "back_edge_estimate": 0,
            "compare_guard_pairs": 0,
            "max_compare_to_branch_distance": 0,
        }

    start = insns[0].address
    end = insns[-1].address + 4
    leaders = {start}
    internal_targets = set()
    back_edges = 0

    for idx, ins in enumerate(insns):
        target = direct_target(ins)
        m = ins.mnemonic.lower()
        if target is not None and start <= target < end and target % 4 == 0:
            internal_targets.add(target)
            leaders.add(target)
            if target < ins.address:
                back_edges += 1
        if (is_cond_branch(m) or is_uncond_branch(m) or m in RETURNS) and idx + 1 < len(insns):
            leaders.add(insns[idx + 1].address)

    compare_guard_pairs = 0
    max_distance = 0
    for i, ins in enumerate(insns):
        if ins.mnemonic.lower() not in COMPARES:
            continue
        for distance in range(1, 4):
            j = i + distance
            if j >= len(insns):
                break
            if is_cond_branch(insns[j].mnemonic):
                compare_guard_pairs += 1
                max_distance = max(max_distance, distance)
                break

    return {
        "basic_block_estimate": len(leaders),
        "internal_direct_branch_targets": len(internal_targets),
        "back_edge_estimate": back_edges,
        "compare_guard_pairs": compare_guard_pairs,
        "max_compare_to_branch_distance": max_distance,
    }


def density(n: int, total: int) -> float:
    return round(n / total, 4) if total else 0.0


def characterize(insns):
    counts = category_counts(insns)
    cfg = cfg_metrics(insns)
    n = counts["instructions"]
    memory = counts["loads"] + counts["stores"]
    guards = counts["compares"] + counts["conditional_branches"]
    calls = counts["direct_calls"] + counts["indirect_calls"]

    densities = {
        "compare_density": density(counts["compares"], n),
        "conditional_branch_density": density(counts["conditional_branches"], n),
        "guard_logic_density": density(guards, n),
        "memory_access_density": density(memory, n),
        "call_density": density(calls, n),
        "arithmetic_density": density(counts["arithmetic"], n),
    }

    if densities["compare_density"] >= 0.10 and densities["conditional_branch_density"] >= 0.08:
        role = "guarded_state_or_validation_logic"
    elif cfg["back_edge_estimate"] and densities["conditional_branch_density"] >= 0.05:
        role = "looping_state_logic"
    elif densities["memory_access_density"] >= 0.25:
        role = "memory_transform_or_copy_logic"
    elif densities["call_density"] >= 0.15:
        role = "call_orchestration_logic"
    else:
        role = "mixed_helper_logic"

    return {
        "counts": counts,
        "densities": densities,
        "cfg": cfg,
        "broad_role_hypothesis": role,
    }


def delta(a, b):
    count_keys = sorted(set(a["counts"]) | set(b["counts"]))
    density_keys = sorted(set(a["densities"]) | set(b["densities"]))
    cfg_keys = sorted(set(a["cfg"]) | set(b["cfg"]))
    return {
        "counts": {k: b["counts"].get(k, 0) - a["counts"].get(k, 0) for k in count_keys},
        "densities": {k: round(b["densities"].get(k, 0.0) - a["densities"].get(k, 0.0), 4) for k in density_keys},
        "cfg": {k: b["cfg"].get(k, 0) - a["cfg"].get(k, 0) for k in cfg_keys},
    }


def candidate_row(triage: dict, candidate_id: str):
    try:
        wanted = int(candidate_id.split("-", 1)[1])
    except Exception as exc:
        raise ValueError("candidate id must look like CAND-001") from exc
    rows = triage.get("ranked_candidates", []) or []
    if wanted < 1 or wanted > len(rows):
        raise ValueError(f"candidate {candidate_id} is outside ranked candidate set")
    return rows[wanted - 1]


def build_report(a_data: bytes, b_data: bytes, triage: dict, candidate_id: str):
    row = candidate_row(triage, candidate_id)
    a_start, a_n = row.get("a_start"), row.get("a_insns")
    b_start, b_n = row.get("b_start"), row.get("b_insns")
    if a_start is None or not a_n or b_start is None or not b_n:
        raise ValueError("candidate requires paired A0 and B0/B1 function views")

    a = characterize(decode(a_data, int(a_start), int(a_n)))
    b = characterize(decode(b_data, int(b_start), int(b_n)))
    return {
        "candidate_id": candidate_id,
        "analysis_kind": "aggregate_static_cfg_dataflow",
        "A15_A0": a,
        "A15_B0_B1": b,
        "B0_B1_minus_A0": delta(a, b),
        "interpretation": {
            "role_change": f"{a['broad_role_hypothesis']} -> {b['broad_role_hypothesis']}",
            "vulnerability_status": "NOT_ESTABLISHED",
            "security_fix_status": "NOT_ESTABLISHED",
        },
        "redactions": [
            "function offsets are not emitted",
            "branch/call targets are not emitted",
            "instruction operands are not emitted",
            "no crafted input or trigger sequence is generated",
        ],
        "limitations": [
            "basic blocks are estimated from static direct-control-flow only",
            "indirect control flow and compiler transformations can distort structural metrics",
            "aggregate structure does not establish attacker reachability or exploitability",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("a15_a0", type=Path)
    ap.add_argument("a15_b0_b1", type=Path)
    ap.add_argument("triage", type=Path)
    ap.add_argument("--candidate", default="CAND-001")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    report = build_report(
        args.a15_a0.read_bytes(),
        args.a15_b0_b1.read_bytes(),
        json.loads(args.triage.read_text(encoding="utf-8")),
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
