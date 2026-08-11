#!/usr/bin/env python3
"""Correlate the LFS hardening with CVE-2026-64747 without claiming identity.

Static analysis only. This extracts calculator-level control and arithmetic
fingerprints from the exact beta 3 target, beta 4, and Apple's fixed 26.6
comparator. It neither derives trigger values nor interacts with AppleAVE2.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

import ave_lfsoutput_dma_candidate as lfs


ARITHMETIC = {
    "add", "adds", "sub", "subs", "mul", "madd", "msub", "smaddl",
    "smull", "umaddl", "umull", "lsl", "lsr", "asr", "sbfm", "ubfm",
    "and", "orr", "eor", "cmp", "cmn", "csel", "csinc", "csinv",
}
XREG = re.compile(r"(?<![A-Za-z0-9_])(?:x(?:[12]?\d|3[01])|xzr)(?![A-Za-z0-9_])")
WREG = re.compile(r"(?<![A-Za-z0-9_])(?:w(?:[12]?\d|3[01])|wzr)(?![A-Za-z0-9_])")
CALC_MARKER = "AVE_CalcBufSizeOfLFSOutput"
GUARD_MARKER = "size >= 0 && size <= 2147483647"


def one_marker_function(macho, marker):
    matches = macho.functions_referencing_marker(marker)
    if len(matches) != 1:
        raise RuntimeError(f"{marker}: expected one function, got {matches}")
    index, function = matches[0]
    if not isinstance(index, int) or not isinstance(function, int):
        raise RuntimeError(f"{marker}: invalid function match {matches[0]!r}")
    return index, function


def fingerprint(macho, index, function):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    counts = {"x64": 0, "w32": 0, "mixed": 0, "neither": 0}
    mnemonics = []
    arithmetic = 0
    for pc, word in macho.words(function):
        decoded = list(md.disasm(word.to_bytes(4, "little"), pc))
        if len(decoded) != 1:
            raise RuntimeError(f"cannot decode 0x{pc:x}")
        insn = decoded[0]
        mnemonics.append(insn.mnemonic)
        if insn.mnemonic not in ARITHMETIC:
            continue
        arithmetic += 1
        has_x, has_w = bool(XREG.search(insn.op_str)), bool(WREG.search(insn.op_str))
        key = "mixed" if has_x and has_w else "x64" if has_x else "w32" if has_w else "neither"
        counts[key] += 1
    guards = {f for _, f in macho.functions_referencing_marker(GUARD_MARKER)}
    return {
        "function_index": index,
        "function": f"0x{function:x}",
        "size": macho.function_size(function),
        "instruction_count": len(mnemonics),
        "arithmetic_count": arithmetic,
        "width_counts": counts,
        "wide_guard": function in guards,
        "mnemonic_sha256": __import__("hashlib").sha256("\n".join(mnemonics).encode()).hexdigest(),
    }


def main():
    if len(sys.argv) != 6:
        raise SystemExit("usage: ave_cve64747_patch_correlation.py <b3-kext> <b4-kext> <fixed-kext> <out.md> <out.json>")
    b3, b4, fixed = (lfs.KextMachO(p) for p in sys.argv[1:4])
    idx3, fn3, fn4 = lfs.find_lfs_calc(b3, b4)
    idx4 = b4.functions.index(fn4)
    idxf, fnf = one_marker_function(fixed, CALC_MARKER)
    builds = {
        "beta3_24A5380h": fingerprint(b3, idx3, fn3),
        "beta4_24A5390f": fingerprint(b4, idx4, fn4),
        "fixed_26_6_23G71": fingerprint(fixed, idxf, fnf),
    }
    b3f, b4f, fixf = builds.values()
    observations = {
        "beta3_lacks_guard": not b3f["wide_guard"],
        "beta4_has_guard": b4f["wide_guard"],
        "fixed_has_guard": fixf["wide_guard"],
        "beta3_32bit_dominant": b3f["width_counts"]["w32"] > b3f["width_counts"]["x64"],
        "beta4_64bit_dominant": b4f["width_counts"]["x64"] > b4f["width_counts"]["w32"],
        "fixed_64bit_dominant": fixf["width_counts"]["x64"] > fixf["width_counts"]["w32"],
    }
    compatible = all(observations.values())
    report = {
        "schema": 1,
        "scope": "offline exact-binary correlation; no trigger generation or device interaction",
        "candidate": "CVE-2026-64747",
        "builds": builds,
        "observations": observations,
        "assessment": {
            "disposition": "deferred-compatible-hardening" if compatible else "deferred-no-correlation",
            "survives": "uncertain" if compatible else "no",
            "identity_claimed": False,
            "proof_gap": "public vulnerable function, crash signature, or researcher patch anchor linking CVE-2026-64747 to this LFS calculator",
        },
    }
    Path(sys.argv[5]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    lines = [
        "# CVE-2026-64747 / AppleAVE2 LFS patch correlation", "",
        "Offline exact-binary evidence only. No trigger values or live service calls.", "",
        "| Build | Function index | Instructions | 64-bit ops | 32-bit ops | Wide-size guard |", "|---|---:|---:|---:|---:|---|",
    ]
    for name, row in builds.items():
        lines.append(f"| `{name}` | {row['function_index']} | {row['instruction_count']} | {row['width_counts']['x64']} | {row['width_counts']['w32']} | {'yes' if row['wide_guard'] else 'no'} |")
    lines += ["", "## Assessment", "", f"Disposition: `{report['assessment']['disposition']}`.", "", "The LFS widening is compatible with the advisory's improved size validation, but binary similarity alone does not identify a CVE. CVE identity remains unconfirmed until a public function, crash signature, or patch anchor maps the advisory to this calculator.", ""]
    Path(sys.argv[4]).write_text("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
