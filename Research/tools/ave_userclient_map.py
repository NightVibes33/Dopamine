#!/usr/bin/env python3
"""Offline AppleAVE2 user-client source-to-sink mapper.

The mapper is intentionally static: it parses the AppleAVE2 Mach-O, resolves the
externalMethod dispatch table, labels handlers from their diagnostic strings and
traces direct BL call paths to named AVE_CalcBufSizeOf* routines. It never opens
an IOKit service and never invokes a kernel method.

Usage:
    ave_userclient_map.py <AppleAVE2 Mach-O> <output.md>
"""

import bisect
import collections
import re
import struct
import sys
from pathlib import Path

LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def signed(value, bits):
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def decode_uleb(data, off, end):
    value = 0
    shift = 0
    while off < end:
        byte = data[off]
        off += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, off
        shift += 7
    return 0, off


def decode_adrp(word, pc):
    imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    imm = signed(imm, 21)
    return (pc & ~0xFFF) + (imm << 12)


class MachO:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.segments = []
        self.function_starts_cmd = None
        self._parse_load_commands()
        self.text = next(seg for seg in self.segments if seg["name"] == "__TEXT")
        self.text_exec = next(seg for seg in self.segments if seg["name"] == "__TEXT_EXEC")
        self.functions = self._parse_function_starts()
        self.strings = self._collect_strings()

    def _parse_load_commands(self):
        ncmds = u32(self.data, 16)
        off = 32
        for _ in range(ncmds):
            cmd = u32(self.data, off)
            cmdsize = u32(self.data, off + 4)
            if cmd == LC_SEGMENT_64:
                name = self.data[off + 8 : off + 24].split(b"\0")[0].decode(errors="replace")
                self.segments.append(
                    {
                        "name": name,
                        "vmaddr": u64(self.data, off + 24),
                        "vmsize": u64(self.data, off + 32),
                        "fileoff": u64(self.data, off + 40),
                        "filesize": u64(self.data, off + 48),
                    }
                )
            elif cmd == LC_FUNCTION_STARTS:
                self.function_starts_cmd = (u32(self.data, off + 8), u32(self.data, off + 12))
            off += cmdsize

    def _parse_function_starts(self):
        if not self.function_starts_cmd:
            return []
        pos, size = self.function_starts_cmd
        end = pos + size
        address = self.text["vmaddr"]
        funcs = []
        while pos < end:
            delta, pos = decode_uleb(self.data, pos, end)
            if delta == 0:
                break
            address += delta
            funcs.append(address)
        return funcs

    def _collect_strings(self):
        strings = {}
        for seg in self.segments:
            if seg["name"] in ("__TEXT_EXEC", "__LINKEDIT"):
                continue
            start = int(seg["fileoff"])
            end = start + int(seg["filesize"])
            i = start
            while i < end:
                if 32 <= self.data[i] < 127:
                    j = i
                    while j < end and 32 <= self.data[j] < 127:
                        j += 1
                    if j < end and self.data[j] == 0 and j - i >= 5:
                        value = self.data[i:j].decode(errors="replace")
                        va = self.fileoff_to_va(i)
                        if va is not None:
                            strings[va] = value
                        i = j + 1
                        continue
                i += 1
        return strings

    def fileoff_to_va(self, fileoff):
        for seg in self.segments:
            start = int(seg["fileoff"])
            end = start + int(seg["filesize"])
            if start <= fileoff < end:
                return int(seg["vmaddr"]) + (fileoff - start)
        return None

    def va_to_fileoff(self, va):
        for seg in self.segments:
            start = int(seg["vmaddr"])
            end = start + int(seg["vmsize"])
            if start <= va < end:
                return int(seg["fileoff"]) + (va - start)
        return None

    def function_for_va(self, va):
        idx = bisect.bisect_right(self.functions, va) - 1
        return self.functions[idx] if idx >= 0 else None

    def function_end(self, start):
        idx = bisect.bisect_left(self.functions, start)
        if idx + 1 < len(self.functions):
            return self.functions[idx + 1]
        return int(self.text_exec["vmaddr"] + self.text_exec["vmsize"])

    def string_refs_in_function(self, start):
        end = self.function_end(start)
        fileoff = self.va_to_fileoff(start)
        end_fileoff = self.va_to_fileoff(end)
        if fileoff is None:
            return []
        if end_fileoff is None:
            end_fileoff = int(self.text_exec["fileoff"] + self.text_exec["filesize"])
        refs = []
        for off in range(fileoff, end_fileoff - 8, 4):
            word = u32(self.data, off)
            if word & 0x9F000000 != 0x90000000:
                continue
            pc = self.fileoff_to_va(off)
            page = decode_adrp(word, pc)
            reg = word & 0x1F
            for delta in range(4, 24, 4):
                nxt = u32(self.data, off + delta)
                target = None
                if nxt & 0x7F000000 == 0x11000000 and ((nxt >> 5) & 0x1F) == reg:
                    imm = (nxt >> 10) & 0xFFF
                    if (nxt >> 22) & 1:
                        imm <<= 12
                    target = page + imm
                elif nxt & 0xFFC00000 == 0xF9400000 and ((nxt >> 5) & 0x1F) == reg:
                    target = page + (((nxt >> 10) & 0xFFF) * 8)
                if target in self.strings:
                    refs.append((pc, self.strings[target]))
                    break
        return refs

    def direct_calls(self, start):
        end = self.function_end(start)
        fileoff = self.va_to_fileoff(start)
        end_fileoff = self.va_to_fileoff(end)
        if fileoff is None:
            return set()
        if end_fileoff is None:
            end_fileoff = int(self.text_exec["fileoff"] + self.text_exec["filesize"])
        calls = set()
        for off in range(fileoff, end_fileoff, 4):
            word = u32(self.data, off)
            if word & 0xFC000000 != 0x94000000:
                continue
            pc = self.fileoff_to_va(off)
            delta = signed(word & 0x03FFFFFF, 26) * 4
            target = (pc + delta) & 0xFFFFFFFFFFFFFFFF
            if self.function_for_va(target) == target:
                calls.add(target)
        return calls

    def find_named_function(self, name):
        needle = name.encode() + b"\0"
        off = self.data.find(needle)
        if off < 0:
            return None
        string_va = self.fileoff_to_va(off)
        if string_va is None:
            return None
        page = string_va & ~0xFFF
        page_off = string_va & 0xFFF
        start = int(self.text_exec["fileoff"])
        end = start + int(self.text_exec["filesize"])
        for fileoff in range(start, end - 24, 4):
            word = u32(self.data, fileoff)
            if word & 0x9F000000 != 0x90000000:
                continue
            pc = self.fileoff_to_va(fileoff)
            if decode_adrp(word, pc) != page:
                continue
            reg = word & 0x1F
            for delta in range(4, 24, 4):
                nxt = u32(self.data, fileoff + delta)
                if nxt & 0x7F000000 != 0x11000000 or ((nxt >> 5) & 0x1F) != reg:
                    continue
                imm = (nxt >> 10) & 0xFFF
                if (nxt >> 22) & 1:
                    imm <<= 12
                if imm == page_off:
                    return self.function_for_va(pc)
        return None


def locate_external_method_and_table(macho):
    start = int(macho.text_exec["fileoff"])
    end = start + int(macho.text_exec["filesize"])
    # 24A5380h AppleAVE2: sub w8,w1,#1; cmp w8,#15; b.hs invalid.
    for off in range(start, end - 80, 4):
        if u32(macho.data, off) != 0x51000428 or u32(macho.data, off + 4) != 0x71003D1F:
            continue
        external_method = macho.function_for_va(macho.fileoff_to_va(off))
        for pos in range(off + 8, off + 80, 4):
            word = u32(macho.data, pos)
            if word & 0x9F000000 != 0x90000000 or (word & 0x1F) != 3:
                continue
            pc = macho.fileoff_to_va(pos)
            page = decode_adrp(word, pc)
            nxt = u32(macho.data, pos + 4)
            if nxt & 0x7F000000 == 0x11000000 and (nxt & 0x1F) == 3 and ((nxt >> 5) & 0x1F) == 3:
                imm = (nxt >> 10) & 0xFFF
                if (nxt >> 22) & 1:
                    imm <<= 12
                return external_method, page + imm
    raise RuntimeError("AppleAVE2 externalMethod selector guard/table not found")


def infer_kernel_collection_base(macho, raw_pointers):
    candidates = collections.Counter()
    for raw in raw_pointers:
        low = raw & 0xFFFFFFFF
        for func in macho.functions:
            base = func - low
            if base & 0xFFF == 0:
                candidates[base] += 1
    if not candidates:
        raise RuntimeError("could not infer kernel-collection base")
    base, hits = candidates.most_common(1)[0]
    return base, hits


def label_handler(macho, handler):
    strings = [value for _, value in macho.string_refs_in_function(handler)]
    for value in strings:
        if re.fullmatch(r"IO_[A-Za-z0-9_]+", value):
            return value
    return "unknown"


def shortest_path(call_graph, source, target, max_depth=8):
    queue = collections.deque([(source, [source])])
    seen = {source}
    while queue:
        node, path = queue.popleft()
        if node == target:
            return path
        if len(path) - 1 >= max_depth:
            continue
        for nxt in call_graph.get(node, ()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, path + [nxt]))
    return None


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: ave_userclient_map.py <AppleAVE2 Mach-O> <output.md>")

    macho = MachO(sys.argv[1])
    external_method, table_va = locate_external_method_and_table(macho)
    table_fileoff = macho.va_to_fileoff(table_va)
    if table_fileoff is None:
        raise RuntimeError("dispatch table is not mapped by a file-backed segment")

    # Index 0 is intentionally empty. externalMethod accepts selectors 1...15.
    entries = []
    raw_pointers = []
    for selector in range(1, 16):
        entry_fileoff = table_fileoff + selector * 0x28
        raw = u64(macho.data, entry_fileoff)
        raw_pointers.append(raw)
        checks = struct.unpack_from("<8I", macho.data, entry_fileoff + 8)
        entries.append((selector, entry_fileoff, raw, checks))

    kc_base, base_hits = infer_kernel_collection_base(macho, raw_pointers)

    call_graph = {func: macho.direct_calls(func) for func in macho.functions}
    calculators = {}
    for match in re.finditer(rb"AVE_CalcBufSizeOf[A-Za-z0-9_]+\x00", macho.data):
        name = match.group()[:-1].decode()
        function = macho.find_named_function(name)
        if function is not None:
            calculators[name] = function

    out = [
        "# AppleAVE2 beta-3 user-client map",
        "",
        "Static/offline analysis only. No IOKit method is invoked by this tool.",
        "",
        f"- `externalMethod`: `0x{external_method:x}`",
        f"- dispatch table: `0x{table_va:x}`",
        "- selector guard: valid selectors are **1 through 15**; index 0 is empty",
        f"- inferred kernel-collection static base: `0x{kc_base:x}` ({base_hits}/15 handler matches)",
        "",
        "## Dispatch table",
        "",
        "| Selector | Method | Handler | Struct in | Struct out | Other raw checks |",
        "|---:|---|---:|---:|---:|---|",
    ]

    handlers = {}
    for selector, _, raw, checks in entries:
        handler = kc_base + (raw & 0xFFFFFFFF)
        handlers[selector] = handler
        method = label_handler(macho, handler)
        # AppleAVE2 stores eight 32-bit check fields after the authenticated action pointer.
        out.append(
            f"| {selector} | `{method}` | `0x{handler:x}` | `0x{checks[1]:x}` | `0x{checks[3]:x}` | "
            f"`{','.join(hex(v) for v in checks[4:])}` |"
        )

    out += ["", "## Named buffer-size paths reachable by direct-call graph", ""]
    any_path = False
    for selector, handler in handlers.items():
        method = label_handler(macho, handler)
        for name, target in sorted(calculators.items()):
            path = shortest_path(call_graph, handler, target)
            if not path:
                continue
            any_path = True
            out.append(f"### selector {selector} `{method}` → `{name}`")
            out.append("")
            out.append(f"Call depth: {len(path)-1}")
            out.append("")
            out.append("`" + " -> ".join(f"0x{va:x}" for va in path) + "`")
            out.append("")
            target_strings = [value for _, value in macho.string_refs_in_function(target)]
            useful = [s for s in target_strings if any(k in s for k in ("width", "height", "bitrate", "frameRate", "bitDepth", "chromaFmt", "size"))]
            for value in useful[:6]:
                out.append(f"- target diagnostic: `{value}`")
            out.append("")

    if not any_path:
        out.append("No named AVE_CalcBufSizeOf* target was reached within eight direct calls.")
        out.append("")

    out += [
        "## Interpretation",
        "",
        "This report establishes static reachability only. A selector-to-calculator path is not proof of a vulnerability or a useful kernel primitive. The next safe proof step is to map which ordinary request fields populate the sizing arguments and confirm reachability on-device without deliberately triggering memory corruption.",
    ]

    Path(sys.argv[2]).write_text("\n".join(out) + "\n")
    print("\n".join(out))


if __name__ == "__main__":
    main()
