#!/usr/bin/env python3
"""Extract caller-side controls for AppleAVE2's LFS size calculator.

Offline static analysis only. This tool inventories exact instructions around
calculator callsites. It does not solve constraints, emit dimensions, open
IOKit, or interact with a device.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

import ave_lfsoutput_dma_candidate as lfs

COND_BRANCHES = {
    "b.eq", "b.ne", "b.hs", "b.lo", "b.mi", "b.pl", "b.vs", "b.vc",
    "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "cbz", "cbnz",
    "tbz", "tbnz",
}
CONTROL_OPS = {"cmp", "cmn", "subs", "ands", "tst", "csel", "csinc", "csinv"}
LOAD_PREFIXES = ("ldr", "ldp", "ldur")


def decode(words):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    rows = []
    for pc, word in words:
        decoded = list(md.disasm(word.to_bytes(4, "little"), pc))
        if len(decoded) != 1:
            raise RuntimeError(f"cannot decode 0x{pc:x}")
        insn = decoded[0]
        rows.append({
            "address": pc,
            "word": f"0x{word:08x}",
            "mnemonic": insn.mnemonic,
            "operands": insn.op_str,
        })
    return rows


def callsites(macho, target):
    found = []
    for index, function in enumerate(macho.functions):
        words = macho.words(function)
        for position, (pc, word) in enumerate(words):
            if lfs.bl_target(pc, word) == target:
                found.append((index, function, position, words))
    return found


def summarize_site(index, function, position, words):
    start = max(0, position - 96)
    end = min(len(words), position + 10)
    window = decode(words[start:end])
    before = window[: position - start]
    controls = [
        row for row in before
        if row["mnemonic"] in CONTROL_OPS or row["mnemonic"] in COND_BRANCHES
    ]
    loads = [row for row in before if row["mnemonic"].startswith(LOAD_PREFIXES)]
    predecessor_calls = []
    for pc, word in words[max(0, position - 96):position]:
        target = lfs.bl_target(pc, word)
        if target is not None:
            predecessor_calls.append({"address": pc, "target": target})
    return {
        "function_index": index,
        "function": function,
        "callsite": words[position][0],
        "window_start": window[0]["address"] if window else function,
        "control_operations": controls,
        "field_loads": loads,
        "predecessor_calls": predecessor_calls,
        "instruction_window": window,
    }


def analyze(path3, path4):
    b3 = lfs.KextMachO(path3)
    b4 = lfs.KextMachO(path4)
    calc_index, calc3, calc4 = lfs.find_lfs_calc(b3, b4)
    sites3 = [summarize_site(*row) for row in callsites(b3, calc3)]
    sites4 = [summarize_site(*row) for row in callsites(b4, calc4)]
    if not sites3 or not sites4:
        raise RuntimeError("calculator caller absent")
    return {
        "target": "iPhone17,3 / 24A5380h",
        "scope": "offline caller-control inventory; no constraint solving or trigger values",
        "calculator_function_index": calc_index,
        "beta3": {
            "calculator": calc3,
            "local_wide_size_guard": False,
            "callsites": sites3,
        },
        "beta4": {
            "calculator": calc4,
            "local_wide_size_guard": True,
            "callsites": sites4,
        },
        "assessment": {
            "disposition": "deferred",
            "survives": "uncertain",
            "proof_gap": (
                "Map each caller-side comparison to the exact geometry field and "
                "prove whether the conjunction bounds the beta3 allocation/DMA inequality."
            ),
        },
    }


def main():
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: ave_lfs_accepted_domain.py <b3-kext> <b4-kext> "
            "<report.md> <result.json>"
        )
    result = analyze(sys.argv[1], sys.argv[2])
    Path(sys.argv[4]).write_text(json.dumps(result, indent=2) + "\n")

    b3 = result["beta3"]
    b4 = result["beta4"]
    lines = [
        "# AppleAVE2 LFS accepted-domain caller controls",
        "",
        "Exact-binary, offline evidence only. No dimensions or driver requests are generated.",
        "",
        f"- Calculator LC_FUNCTION_STARTS index: \`{result['calculator_function_index']}\`",
        f"- Beta 3 calculator: \`0x{b3['calculator']:x}\`; local signed-31-bit guard: absent",
        f"- Beta 4 calculator: \`0x{b4['calculator']:x}\`; local signed-31-bit guard: present",
        f"- Beta 3 callsites: {len(b3['callsites'])}; beta 4 callsites: {len(b4['callsites'])}",
        "",
        "| Build | Caller | Callsite | Pre-call controls | Field loads | Predecessor calls |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for build, group in (("beta3", b3), ("beta4", b4)):
        for site in group["callsites"]:
            lines.append(
                f"| {build} | \`0x{site['function']:x}\` | \`0x{site['callsite']:x}\` | "
                f"{len(site['control_operations'])} | {len(site['field_loads'])} | "
                f"{len(site['predecessor_calls'])} |"
            )
    lines += [
        "",
        "## Validation assessment",
        "",
        "The artifact preserves each caller instruction window and separately inventories "
        "loads, comparisons, conditional branches, and predecessor calls. Nearby controls "
        "are evidence anchors only; they are not treated as field-specific bounds until "
        "their register dependencies are traced.",
        "",
        "**Deferred; candidate survives as uncertain.** The remaining proof gap is to map "
        "caller controls to exact geometry fields and prove or falsify the accepted-domain "
        "allocation-versus-DMA inequality.",
    ]
    Path(sys.argv[3]).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
