#!/usr/bin/env python3
"""Emit exact host/FW LFS arithmetic evidence for offline formula review.

This helper deliberately does not solve for input dimensions or interact with
AppleAVE2.  It preserves the two relevant instruction streams and highlights
arithmetic/memory operations so a later validator can build a proper SSA/data-
flow comparison without relying on guessed pseudocode.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

import ave_lfsoutput_dma_candidate as lfs


ARITHMETIC = {
    "add", "adds", "sub", "subs", "mul", "madd", "msub", "smaddl",
    "smull", "umaddl", "umull", "lsl", "lsr", "asr", "sbfm", "ubfm",
    "and", "orr", "eor", "cmp", "cmn", "csel", "csinc", "csinv",
}
MEMORY_PREFIXES = ("ldr", "ldp", "str", "stp")


def disassemble(words):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    rows = []
    for pc, word in words:
        decoded = list(md.disasm(word.to_bytes(4, "little"), pc))
        if len(decoded) != 1:
            raise RuntimeError(f"cannot decode instruction at 0x{pc:x}")
        insn = decoded[0]
        rows.append({
            "address": pc,
            "word": f"0x{word:08x}",
            "mnemonic": insn.mnemonic,
            "operands": insn.op_str,
            "arithmetic": insn.mnemonic in ARITHMETIC,
            "memory": insn.mnemonic.startswith(MEMORY_PREFIXES),
        })
    return rows


def summarize(rows):
    return {
        "instruction_count": len(rows),
        "arithmetic_count": sum(row["arithmetic"] for row in rows),
        "memory_count": sum(row["memory"] for row in rows),
        "arithmetic": [row for row in rows if row["arithmetic"]],
        "memory": [row for row in rows if row["memory"]],
    }


def analyze(k3_path, k4_path, fw3_path, fw4_path):
    result = lfs.analyze(k3_path, k4_path, fw3_path, fw4_path)
    k3 = lfs.KextMachO(k3_path)
    k4 = lfs.KextMachO(k4_path)
    f3 = lfs.PreloadMachO(fw3_path)
    f4 = lfs.PreloadMachO(fw4_path)

    streams = {
        "beta3_host_lfs_calculator": disassemble(k3.words(result["calc3"])),
        "beta4_host_lfs_calculator": disassemble(k4.words(result["calc4"])),
        "beta3_fw_lfs_write_dma": disassemble(f3.words(result["fw3"]["start"])),
        "beta4_fw_lfs_write_dma": disassemble(f4.words(result["fw4"]["start"])),
    }
    return result, streams


def main():
    if len(sys.argv) != 7:
        raise SystemExit(
            "usage: ave_lfs_formula_evidence.py <b3-kext> <b4-kext> "
            "<b3-fw> <b4-fw> <report.md> <evidence.json>"
        )
    result, streams = analyze(*sys.argv[1:5])
    evidence = {
        "scope": "static/offline; no trigger values; no device interaction",
        "target": "iPhone17,3 / 24A5380h",
        "functions": {
            "beta3_host": f"0x{result['calc3']:x}",
            "beta4_host": f"0x{result['calc4']:x}",
            "beta3_firmware": f"0x{result['fw3']['start']:x}",
            "beta4_firmware": f"0x{result['fw4']['start']:x}",
        },
        "streams": {name: summarize(rows) for name, rows in streams.items()},
    }
    Path(sys.argv[6]).write_text(json.dumps(evidence, indent=2) + "\n")

    lines = [
        "# AppleAVE2 LFS formula evidence bundle",
        "",
        "Static/offline evidence only. No triggering dimensions are generated.",
        "",
        f"- beta3 host LFS calculator: `0x{result['calc3']:x}`",
        f"- beta4 host LFS calculator: `0x{result['calc4']:x}`",
        f"- beta3 H17 write-DMA routine: `0x{result['fw3']['start']:x}`",
        f"- beta4 H17 write-DMA routine: `0x{result['fw4']['start']:x}`",
        "",
        "| Stream | Instructions | Arithmetic | Memory |",
        "|---|---:|---:|---:|",
    ]
    for name, rows in streams.items():
        summary = summarize(rows)
        lines.append(
            f"| `{name}` | {summary['instruction_count']} | "
            f"{summary['arithmetic_count']} | {summary['memory_count']} |"
        )
    lines += [
        "",
        "## Disposition",
        "",
        "The JSON artifact preserves every decoded instruction plus focused arithmetic and memory-operation inventories for both sides of the suspected size/extent mismatch. It is suitable input for a subsequent SSA/data-dependency comparison.",
        "",
        "This stage does not establish formula divergence, memory corruption, or a kernel primitive. It closes the evidence-extraction prerequisite without guessing pseudocode or producing a triggering dimension pair.",
    ]
    Path(sys.argv[5]).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
