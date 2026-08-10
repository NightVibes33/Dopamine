#!/usr/bin/env python3
"""Offline AppleAVE2 coded-data size-to-allocation sink validator.

Static analysis only. It never opens IOKit, invokes an external method, or
modifies firmware. It builds on ave_dimension_flow_map.py to ensure the size
producer is the same selector-4 path whose width/height propagation was proven.
"""
import bisect
import collections
import struct
import sys
from pathlib import Path

import ave_dimension_flow_map as dimension_flow

LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26


def u32(data, off): return struct.unpack_from('<I', data, off)[0]
def u64(data, off): return struct.unpack_from('<Q', data, off)[0]
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
    return (pc & ~0xFFF) + (signed(imm, 21) << 12)


class MachO:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self.segments = []
        self.function_starts_cmd = None
        off = 32
        for _ in range(u32(self.data, 16)):
            cmd = u32(self.data, off)
            cmdsize = u32(self.data, off + 4)
            if cmd == LC_SEGMENT_64:
                name = self.data[off + 8:off + 24].split(b'\0')[0].decode(errors='replace')
                self.segments.append({
                    'name': name,
                    'vmaddr': u64(self.data, off + 24),
                    'vmsize': u64(self.data, off + 32),
                    'fileoff': u64(self.data, off + 40),
                    'filesize': u64(self.data, off + 48),
                })
            elif cmd == LC_FUNCTION_STARTS:
                self.function_starts_cmd = (u32(self.data, off + 8), u32(self.data, off + 12))
            off += cmdsize

        self.text = next(seg for seg in self.segments if seg['name'] == '__TEXT')
        self.text_exec = next(seg for seg in self.segments if seg['name'] == '__TEXT_EXEC')
        pos, size = self.function_starts_cmd
        end = pos + size
        address = self.text['vmaddr']
        self.functions = []
        while pos < end:
            delta, pos = decode_uleb(self.data, pos, end)
            if not delta:
                break
            address += delta
            self.functions.append(address)

    def va_to_fileoff(self, va):
        for seg in self.segments:
            if seg['vmaddr'] <= va < seg['vmaddr'] + seg['vmsize']:
                return seg['fileoff'] + va - seg['vmaddr']
        return None

    def fileoff_to_va(self, fileoff):
        for seg in self.segments:
            if seg['fileoff'] <= fileoff < seg['fileoff'] + seg['filesize']:
                return seg['vmaddr'] + fileoff - seg['fileoff']
        return None

    def function_for_va(self, va):
        idx = bisect.bisect_right(self.functions, va) - 1
        return self.functions[idx] if idx >= 0 else None

    def function_end(self, start):
        idx = bisect.bisect_left(self.functions, start)
        return self.functions[idx + 1] if idx + 1 < len(self.functions) else self.text_exec['vmaddr'] + self.text_exec['vmsize']

    def words(self, start):
        begin = self.va_to_fileoff(start)
        end = self.va_to_fileoff(self.function_end(start))
        return [(self.fileoff_to_va(off), u32(self.data, off)) for off in range(begin, end, 4)]

    def direct_calls(self, start):
        calls = []
        for pc, word in self.words(start):
            if word & 0xFC000000 != 0x94000000:
                continue
            target = (pc + signed(word & 0x03FFFFFF, 26) * 4) & 0xFFFFFFFFFFFFFFFF
            if self.function_for_va(target) == target:
                calls.append(target)
        return calls

    def refs_to_exact_string(self, value):
        fileoff = self.data.find(value.encode() + b'\0')
        if fileoff < 0:
            return []
        va = self.fileoff_to_va(fileoff)
        page = va & ~0xFFF
        page_off = va & 0xFFF
        refs = []
        start = self.text_exec['fileoff']
        end = start + self.text_exec['filesize']
        for off in range(start, end - 24, 4):
            word = u32(self.data, off)
            if word & 0x9F000000 != 0x90000000:
                continue
            pc = self.fileoff_to_va(off)
            if decode_adrp(word, pc) != page:
                continue
            reg = word & 31
            for delta in range(4, 24, 4):
                nxt = u32(self.data, off + delta)
                if nxt & 0x7F000000 != 0x11000000 or ((nxt >> 5) & 31) != reg:
                    continue
                imm = (nxt >> 10) & 0xFFF
                if (nxt >> 22) & 1:
                    imm <<= 12
                if imm == page_off:
                    refs.append(pc)
                    break
        return refs


def bl_target(pc, word):
    if word & 0xFC000000 != 0x94000000:
        return None
    return (pc + signed(word & 0x03FFFFFF, 26) * 4) & 0xFFFFFFFFFFFFFFFF


def ldr_w_uimm(word):
    if word & 0xFFC00000 == 0xB9400000:
        return word & 31, (word >> 5) & 31, ((word >> 10) & 0xFFF) * 4
    return None


def str_w_uimm(word):
    if word & 0xFFC00000 == 0xB9000000:
        return word & 31, (word >> 5) & 31, ((word >> 10) & 0xFFF) * 4
    return None


def mov_x(word):
    if word & 0xFFE0FFE0 == 0xAA0003E0:
        return word & 31, (word >> 16) & 31
    return None


def shortest_path(macho, source, target, max_depth=12):
    queue = collections.deque([(source, [source])])
    seen = {source}
    while queue:
        node, path = queue.popleft()
        if node == target:
            return path
        if len(path) - 1 >= max_depth:
            continue
        for nxt in macho.direct_calls(node):
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, path + [nxt]))
    return None


def analyze(beta3_path, beta4_path):
    flow = dimension_flow.analyze(beta3_path, beta4_path)
    macho = MachO(beta3_path)
    coded_calc = flow['coded_calc']
    coded_caller = flow['coded_caller']

    size_field = None
    words = macho.words(coded_caller)
    for index, (pc, word) in enumerate(words[:-1]):
        if bl_target(pc, word) != coded_calc:
            continue
        store = str_w_uimm(words[index + 1][1])
        if store and store[0] == 0:
            size_field = store[2]
            break
    if size_field is None:
        raise RuntimeError('coded-data result field not found in proven dimension-flow caller')

    refs = macho.refs_to_exact_string('AVE_CreateExternalOutSurfaces')
    if not refs:
        raise RuntimeError('AVE_CreateExternalOutSurfaces not found')
    allocator = macho.function_for_va(refs[0])

    required_size_load = None
    surface_create = None
    allocator_words = macho.words(allocator)
    for index, (pc, word) in enumerate(allocator_words):
        load = ldr_w_uimm(word)
        if not load or load[2] != size_field:
            continue
        size_reg = load[0]
        for pos in range(index + 1, min(index + 90, len(allocator_words))):
            move = mov_x(allocator_words[pos][1])
            if move != (4, size_reg):
                continue
            target = None
            for scan in range(pos + 1, min(pos + 9, len(allocator_words))):
                later_move = mov_x(allocator_words[scan][1])
                if later_move and later_move[0] == 4:
                    break
                candidate = bl_target(allocator_words[scan][0], allocator_words[scan][1])
                if candidate:
                    target = candidate
                    break
            if target:
                required_size_load = pc
                surface_create = target
                break
        if surface_create:
            break
    if surface_create is None:
        raise RuntimeError('coded-data required size is not proven to reach a surface create/replacement call')

    path = shortest_path(macho, flow['selector4'], allocator)
    if not path:
        raise RuntimeError('selector-4 path to AVE_CreateExternalOutSurfaces not found')

    return {
        'selector4': flow['selector4'],
        'coded_calc': coded_calc,
        'coded_caller': coded_caller,
        'size_field': size_field,
        'allocator': allocator,
        'required_size_load': required_size_load,
        'surface_create': surface_create,
        'path': path,
    }


def main():
    if len(sys.argv) != 4:
        raise SystemExit('usage: ave_codeddata_sink_map.py <beta3-AppleAVE2> <beta4-AppleAVE2> <output.md>')
    result = analyze(sys.argv[1], sys.argv[2])
    out = [
        '# AppleAVE2 coded-data allocation sink',
        '',
        'Static/offline validation only; no IOKit calls or firmware modification.',
        '',
        f"- selector 4 handler: `0x{result['selector4']:x}`",
        f"- coded-data size calculator: `0x{result['coded_calc']:x}`",
        f"- proven dimension-flow caller: `0x{result['coded_caller']:x}`",
        f"- returned coded-data size field: descriptor `+0x{result['size_field']:x}`",
        f"- `AVE_CreateExternalOutSurfaces`: `0x{result['allocator']:x}`",
        f"- required-size load: `0x{result['required_size_load']:x}`",
        f"- surface create/replacement call: `0x{result['surface_create']:x}` with required size passed as argument 4",
        '',
        '## Selector-4 path to surface management',
        '',
        '`' + ' -> '.join(f"0x{value:x}" for value in result['path']) + '`',
        '',
        '## Conclusion',
        '',
        'The coded-data size derived from selector-4 frame dimensions is stored in the buffer-size descriptor and later consumed by AVE_CreateExternalOutSurfaces as the required size for a surface create/replacement operation.',
        '',
        'This proves a static input-to-size-to-allocation chain. It does not demonstrate corruption and does not provide a triggering input.',
    ]
    Path(sys.argv[3]).write_text('\n'.join(out) + '\n')
    print('\n'.join(out))


if __name__ == '__main__':
    main()
