#!/usr/bin/env python3
"""Map beta-new validation strings to AppleAVE2 Mach-O functions.

Research helper only. It does not trigger an exploit or modify firmware.

Usage:
    ave_validation_map.py <new-kext> <comm-diff> <output>

`comm-diff` is produced by:
    comm -3 old.strings new.strings
where lines beginning with a TAB are new-only.
"""

import bisect
import re
import struct
import sys
from pathlib import Path

LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26

VALIDATION_RE = re.compile(
    r"overflow|out of range|>= 0|<= 2147483647|invalid command slot",
    re.IGNORECASE,
)
NAME_RE = re.compile(r"^AVE_CalcBufSizeOf")


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def decode_uleb(data, off, end):
    value = 0
    shift = 0
    while off < end:
        byte = data[off]
        off += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, off
        shift += 7
    return 0, off


def parse_macho(path):
    data = Path(path).read_bytes()
    ncmds = u32(data, 16)
    off = 32
    segments = []
    function_starts_cmd = None

    for _ in range(ncmds):
        cmd = u32(data, off)
        cmdsize = u32(data, off + 4)
        if cmd == LC_SEGMENT_64:
            name = data[off + 8 : off + 24].split(b"\0")[0].decode(errors="replace")
            segments.append(
                {
                    "name": name,
                    "vmaddr": u64(data, off + 24),
                    "vmsize": u64(data, off + 32),
                    "fileoff": u64(data, off + 40),
                    "filesize": u64(data, off + 48),
                }
            )
        elif cmd == LC_FUNCTION_STARTS:
            function_starts_cmd = (u32(data, off + 8), u32(data, off + 12))
        off += cmdsize

    text = next(seg for seg in segments if seg["name"] == "__TEXT")
    text_exec = next(seg for seg in segments if seg["name"] == "__TEXT_EXEC")

    functions = []
    if function_starts_cmd:
        pos, size = function_starts_cmd
        end = pos + size
        address = text["vmaddr"]
        while pos < end:
            delta, pos = decode_uleb(data, pos, end)
            if delta == 0:
                break
            address += delta
            functions.append(address)

    return data, segments, text_exec, functions


def fileoff_to_va(segments, fileoff):
    for seg in segments:
        start = seg["fileoff"]
        end = start + seg["filesize"]
        if start <= fileoff < end:
            return seg["vmaddr"] + (fileoff - start)
    return None


def decode_adrp(insn, pc):
    immhi = (insn >> 5) & 0x7FFFF
    immlo = (insn >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def find_refs(data, text_exec, target_va):
    target_page = target_va & ~0xFFF
    target_off = target_va & 0xFFF
    start = int(text_exec["fileoff"])
    end = int(start + text_exec["filesize"])
    base_va = int(text_exec["vmaddr"])
    refs = set()

    for fileoff in range(start, end - 24, 4):
        insn = u32(data, fileoff)
        if (insn & 0x9F000000) != 0x90000000:  # ADRP
            continue
        pc = base_va + (fileoff - start)
        if decode_adrp(insn, pc) != target_page:
            continue
        adrp_reg = insn & 0x1F

        for delta in range(4, 24, 4):
            nxt = u32(data, fileoff + delta)
            # ADD (immediate), 32/64-bit family.
            if (nxt & 0x7F000000) == 0x11000000:
                rn = (nxt >> 5) & 0x1F
                imm = (nxt >> 10) & 0xFFF
                shift = (nxt >> 22) & 1
                value = imm << (12 if shift else 0)
                if rn == adrp_reg and value == target_off:
                    refs.add(pc)
                    break

    return sorted(refs)


def function_for_ref(functions, ref):
    idx = bisect.bisect_right(functions, ref) - 1
    if idx < 0:
        return None
    start = functions[idx]
    end = functions[idx + 1] if idx + 1 < len(functions) else None
    return start, end


def locate_string(data, segments, value):
    raw = value.encode(errors="ignore")
    pos = data.find(raw)
    if pos < 0:
        return None, []
    va = fileoff_to_va(segments, pos)
    return va, pos


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: ave_validation_map.py <new-kext> <comm-diff> <output>")

    kext_path, diff_path, output_path = map(Path, sys.argv[1:])
    data, segments, text_exec, functions = parse_macho(kext_path)

    new_only = []
    for line in diff_path.read_text(errors="replace").splitlines():
        if line.startswith("\t"):
            new_only.append(line[1:])

    validation_strings = sorted({s for s in new_only if VALIDATION_RE.search(s)})
    calc_names = sorted({s for s in new_only if NAME_RE.search(s)})

    function_names = {}
    for name in calc_names:
        va, _ = locate_string(data, segments, name)
        if va is None:
            continue
        for ref in find_refs(data, text_exec, va):
            found = function_for_ref(functions, ref)
            if found:
                function_names.setdefault(found[0], set()).add(name)

    rows = []
    for value in validation_strings:
        va, _ = locate_string(data, segments, value)
        if va is None:
            continue
        for ref in find_refs(data, text_exec, va):
            found = function_for_ref(functions, ref)
            if not found:
                continue
            start, end = found
            rows.append(
                {
                    "function": start,
                    "size": (end - start) if end else 0,
                    "validation": value,
                    "names": sorted(function_names.get(start, [])),
                }
            )

    rows.sort(key=lambda row: (row["function"], row["validation"]))

    out = []
    out.append("# AppleAVE2 beta-new validation map")
    out.append("")
    out.append(f"Functions discovered from LC_FUNCTION_STARTS: {len(functions)}")
    out.append(f"New-only validation strings: {len(validation_strings)}")
    out.append(f"Mapped validation references: {len(rows)}")
    out.append("")

    current = None
    for row in rows:
        if row["function"] != current:
            current = row["function"]
            out.append(f"## function 0x{current:x} size=0x{row['size']:x}")
            if row["names"]:
                out.append("names: " + ", ".join(row["names"]))
        out.append("- " + row["validation"])

    Path(output_path).write_text("\n".join(out) + "\n")
    print("\n".join(out))


if __name__ == "__main__":
    main()
