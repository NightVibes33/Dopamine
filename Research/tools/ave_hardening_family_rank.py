#!/usr/bin/env python3
"""Rank beta3 AppleAVE2 sibling hardening paths for static follow-up.

The ranker anchors on explicit beta4 overflow diagnostics, maps their code xrefs
to LC_FUNCTION_STARTS, pairs the same function index back to beta3, measures
function growth, and counts direct beta3 callers.

This is a triage heuristic only. It performs no device interaction and derives
no triggering values.
"""
import bisect
import struct
import sys
from collections import defaultdict
from pathlib import Path

LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26

MARKERS = [
    ("DPB", "DPB size overflow"),
    ("LRB", "LRB size overflow"),
    ("HSCOutput", "HSCOutput size overflow"),
    ("MCTFOutput", "MCTFOutput size overflow"),
    ("PixelArea", "pixel area overflow"),
]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def signed(value, bits):
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def decode_uleb(data, offset, end):
    value = 0
    shift = 0
    while offset < end:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    return 0, offset


def decode_adrp(word, pc):
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    return (pc & ~0xFFF) + (signed(immediate, 21) << 12)


def decode_bl_target(pc, word):
    if word & 0xFC000000 != 0x94000000:
        return None
    return pc + (signed(word & 0x03FFFFFF, 26) << 2)


class MachO:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self.segments = []
        function_starts_command = None

        offset = 32
        for _ in range(u32(self.data, 16)):
            command = u32(self.data, offset)
            command_size = u32(self.data, offset + 4)
            if command == LC_SEGMENT_64:
                name = self.data[offset + 8:offset + 24].split(b"\0")[0].decode(
                    errors="replace"
                )
                self.segments.append(
                    {
                        "name": name,
                        "vmaddr": u64(self.data, offset + 24),
                        "vmsize": u64(self.data, offset + 32),
                        "fileoff": u64(self.data, offset + 40),
                        "filesize": u64(self.data, offset + 48),
                    }
                )
            elif command == LC_FUNCTION_STARTS:
                function_starts_command = (
                    u32(self.data, offset + 8),
                    u32(self.data, offset + 12),
                )
            offset += command_size

        self.text = next(seg for seg in self.segments if seg["name"] == "__TEXT")
        self.text_exec = next(
            seg for seg in self.segments if seg["name"] == "__TEXT_EXEC"
        )
        if function_starts_command is None:
            raise RuntimeError("LC_FUNCTION_STARTS missing")

        offset, size = function_starts_command
        end = offset + size
        address = self.text["vmaddr"]
        self.functions = []
        while offset < end:
            delta, offset = decode_uleb(self.data, offset, end)
            if not delta:
                break
            address += delta
            self.functions.append(address)

    def fileoff_to_va(self, fileoff):
        for segment in self.segments:
            if segment["fileoff"] <= fileoff < segment["fileoff"] + segment["filesize"]:
                return segment["vmaddr"] + fileoff - segment["fileoff"]
        return None

    def function_for_va(self, va):
        index = bisect.bisect_right(self.functions, va) - 1
        if index < 0:
            return None, None
        return index, self.functions[index]

    def function_size(self, index):
        if index + 1 < len(self.functions):
            end = self.functions[index + 1]
        else:
            end = self.text_exec["vmaddr"] + self.text_exec["vmsize"]
        return end - self.functions[index]

    def exact_strings_containing(self, marker):
        needle = marker.encode()
        results = {}
        position = 0
        while True:
            hit = self.data.find(needle, position)
            if hit < 0:
                break
            start = self.data.rfind(b"\0", 0, hit) + 1
            end = self.data.find(b"\0", hit)
            if end < 0:
                break
            try:
                value = self.data[start:end].decode()
            except UnicodeDecodeError:
                value = ""
            if marker in value:
                va = self.fileoff_to_va(start)
                if va is not None:
                    results[va] = value
            position = hit + len(needle)
        return list(results.items())

    def xrefs_to_va(self, target_va):
        page = target_va & ~0xFFF
        page_offset = target_va & 0xFFF
        references = []
        begin = self.text_exec["fileoff"]
        end = begin + self.text_exec["filesize"]

        for fileoff in range(begin, end - 24, 4):
            word = u32(self.data, fileoff)
            if word & 0x9F000000 != 0x90000000:
                continue
            pc = self.fileoff_to_va(fileoff)
            if decode_adrp(word, pc) != page:
                continue
            register = word & 31
            for delta in range(4, 24, 4):
                next_word = u32(self.data, fileoff + delta)
                if next_word & 0x7F000000 != 0x11000000:
                    continue
                if ((next_word >> 5) & 31) != register:
                    continue
                immediate = (next_word >> 10) & 0xFFF
                if (next_word >> 22) & 1:
                    immediate <<= 12
                if immediate == page_offset:
                    references.append(pc)
                    break
        return references

    def direct_call_counts(self, targets):
        counts = defaultdict(int)
        target_set = set(targets)
        begin = self.text_exec["fileoff"]
        end = begin + self.text_exec["filesize"]
        for fileoff in range(begin, end - 4, 4):
            pc = self.fileoff_to_va(fileoff)
            target = decode_bl_target(pc, u32(self.data, fileoff))
            if target in target_set:
                counts[target] += 1
        return counts


def analyze(beta3_path, beta4_path):
    beta3 = MachO(beta3_path)
    beta4 = MachO(beta4_path)
    rows = []

    for label, marker in MARKERS:
        indices = set()
        for string_va, _ in beta4.exact_strings_containing(marker):
            for reference in beta4.xrefs_to_va(string_va):
                index, _ = beta4.function_for_va(reference)
                if index is not None:
                    indices.add(index)

        for index in sorted(indices):
            if index >= len(beta3.functions):
                continue
            rows.append(
                {
                    "label": label,
                    "marker": marker,
                    "index": index,
                    "beta3": beta3.functions[index],
                    "beta4": beta4.functions[index],
                    "beta3_size": beta3.function_size(index),
                    "beta4_size": beta4.function_size(index),
                }
            )

    beta3_calls = beta3.direct_call_counts([row["beta3"] for row in rows])
    beta4_calls = beta4.direct_call_counts([row["beta4"] for row in rows])

    for row in rows:
        row["delta"] = row["beta4_size"] - row["beta3_size"]
        row["beta3_calls"] = beta3_calls[row["beta3"]]
        row["beta4_calls"] = beta4_calls[row["beta4"]]

    rows.sort(key=lambda row: (row["beta3_calls"], row["delta"]), reverse=True)
    return rows


def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: ave_hardening_family_rank.py <beta3-AppleAVE2> <beta4-AppleAVE2> <output.md>"
        )

    rows = analyze(sys.argv[1], sys.argv[2])
    if not rows:
        raise RuntimeError("no hardening-family marker xrefs found")

    lines = [
        "# AppleAVE2 sibling hardening triage",
        "",
        "Static/offline prioritization only. No device interaction or trigger generation.",
        "",
        "| Rank | Marker family | function index | beta3 VA | beta3 size | beta4 size | delta | beta3 direct calls |",
        "|---:|---|---:|---:|---:|---:|---:|---:|",
    ]

    for rank, row in enumerate(rows, 1):
        lines.append(
            f"| {rank} | {row['label']} | {row['index']} | `0x{row['beta3']:x}` | 0x{row['beta3_size']:x} | 0x{row['beta4_size']:x} | +0x{row['delta']:x} | {row['beta3_calls']} |"
        )

    lines += [
        "",
        "## Interpretation",
        "",
        "Rows are ranked first by beta3 direct-call exposure and then by beta3->beta4 function growth. This is a triage heuristic, not exploitability proof. Each row still needs an independent source -> arithmetic -> allocation/map -> consumer/bound proof tuple.",
        "",
        "CodedData is intentionally excluded from this sibling ranking because its kernel-to-firmware path now serves as a negative control: the actual backing-surface size is propagated downstream and consumed as a firmware-side bound.",
    ]

    Path(sys.argv[3]).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
