#!/usr/bin/env python3
"""Collect fail-closed evidence for the AppleAVE2 LRB surface identity.

This is an offline disassembly probe.  It deliberately does not derive frame
dimensions, invoke an IOKit selector, or claim that proximity proves identity.
"""
import struct
import sys
from pathlib import Path

from ave_hardening_family_rank import MachO, decode_bl_target

LRB_SIZE_FIELD = 0x31C
LRB_ALLOC_ANCHOR = 0xFFFFFFF0087DDA28
SURFACE_EXPORT_HELPER = 0xFFFFFFF0087D103C


def va_to_fileoff(macho, va):
    for segment in macho.segments:
        if segment["vmaddr"] <= va < segment["vmaddr"] + segment["vmsize"]:
            return segment["fileoff"] + va - segment["vmaddr"]
    raise RuntimeError(f"cannot map VA 0x{va:x}")


def words_for_function(macho, index):
    start = macho.functions[index]
    size = macho.function_size(index)
    fileoff = va_to_fileoff(macho, start)
    return [
        (start + delta, struct.unpack_from("<I", macho.data, fileoff + delta)[0])
        for delta in range(0, size, 4)
    ]


def field_access(word, offset):
    # 32-bit unsigned-immediate LDR/STR. Offset is scaled by four.
    if word & 0xFFC00000 not in (0xB9400000, 0xB9000000):
        return None
    if ((word >> 10) & 0xFFF) * 4 != offset:
        return None
    kind = "ldr" if word & 0xFFC00000 == 0xB9400000 else "str"
    return kind, word & 31, (word >> 5) & 31


def function_index_for(macho, va):
    index, start = macho.function_for_va(va)
    if index is None:
        raise RuntimeError(f"no function contains 0x{va:x}")
    return index, start


def collect(macho):
    alloc_index, alloc_function = function_index_for(macho, LRB_ALLOC_ANCHOR)
    string_rows = []
    for marker in ("invalid LRB firmware buffer", "LRB firmware buffer"):
        for string_va, value in macho.exact_strings_containing(marker):
            for xref in macho.xrefs_to_va(string_va):
                index, function = function_index_for(macho, xref)
                string_rows.append((value, string_va, xref, index, function))

    field_rows = []
    export_calls = []
    for index, _ in enumerate(macho.functions):
        for pc, word in words_for_function(macho, index):
            access = field_access(word, LRB_SIZE_FIELD)
            if access:
                field_rows.append((index, macho.functions[index], pc, access, word))
            target = decode_bl_target(pc, word)
            if target == SURFACE_EXPORT_HELPER:
                export_calls.append((index, macho.functions[index], pc))

    return {
        "alloc_index": alloc_index,
        "alloc_function": alloc_function,
        "strings": sorted(set(string_rows), key=lambda row: (row[4], row[2])),
        "fields": field_rows,
        "exports": export_calls,
    }


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: ave_lrb_identity_probe.py <beta3-AppleAVE2> <output.md>")
    macho = MachO(sys.argv[1])
    result = collect(macho)
    interesting = {result["alloc_index"]}
    interesting.update(row[3] for row in result["strings"])
    interesting.update(row[0] for row in result["fields"])
    interesting.update(row[0] for row in result["exports"])

    lines = [
        "# AppleAVE2 LRB identity evidence probe",
        "",
        "Static/offline evidence only. Function co-location and call proximity are not treated as proof of surface identity.",
        "",
        f"- allocation anchor `0x{LRB_ALLOC_ANCHOR:x}` is in function index `{result['alloc_index']}` at `0x{result['alloc_function']:x}`.",
        f"- descriptor field under investigation: `+0x{LRB_SIZE_FIELD:x}`.",
        f"- known actual-size export helper: `0x{SURFACE_EXPORT_HELPER:x}`.",
        "",
        "## LRB diagnostic xrefs",
        "",
    ]
    if result["strings"]:
        for value, string_va, xref, index, function in result["strings"]:
            lines.append(f"- `{value}` at `0x{string_va:x}` -> xref `0x{xref:x}` -> function `{index}` / `0x{function:x}`")
    else:
        lines.append("- none found (probe remains inconclusive)")

    lines += ["", "## Exact +0x31c accesses", ""]
    for index, function, pc, access, word in result["fields"]:
        kind, rt, rn = access
        lines.append(f"- function `{index}` / `0x{function:x}`: `{kind} w{rt}, [x{rn}, #0x31c]` at `0x{pc:x}` (`0x{word:08x}`)")

    lines += ["", "## Calls to actual-size export helper", ""]
    for index, function, pc in result["exports"]:
        lines.append(f"- function `{index}` / `0x{function:x}` calls export helper at `0x{pc:x}`")

    lines += ["", "## Relevant function instruction words", ""]
    for index in sorted(interesting):
        lines.append(f"### function `{index}` / `0x{macho.functions[index]:x}`")
        lines.append("")
        lines.append("```text")
        for pc, word in words_for_function(macho, index):
            target = decode_bl_target(pc, word)
            suffix = f"  BL 0x{target:x}" if target is not None else ""
            lines.append(f"0x{pc:x}: 0x{word:08x}{suffix}")
        lines.append("```")
        lines.append("")

    lines += [
        "## Disposition",
        "",
        "This probe only inventories exact anchors needed for the identity proof. A later validator must establish register/object continuity from the LRB allocation slot to a specific export-helper call before the identity checkbox can be closed.",
    ]
    Path(sys.argv[2]).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
