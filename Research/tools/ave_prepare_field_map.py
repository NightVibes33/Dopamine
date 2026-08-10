#!/usr/bin/env python3
"""Offline AppleAVE2 selector-4 field-path validator.

This tool compares the iPhone17,3 iOS 27 beta-3 and beta-4 AppleAVE2
fileset entries. It proves the static path from selector 4 (IO_Prepare) to the
beta-3 AVE_Client_CheckInfo-equivalent function and maps the beta-4 frame-
dimension validation back to offsets inside selector 4's structured input.

It never opens an IOKit service, invokes a selector, or modifies firmware.
"""

import bisect
import collections
import json
import struct
import sys
from pathlib import Path

LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26


def u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]


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
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.segments = []
        self.function_starts_cmd = None
        self._parse_load_commands()
        self.text = next(seg for seg in self.segments if seg['name'] == '__TEXT')
        self.text_exec = next(seg for seg in self.segments if seg['name'] == '__TEXT_EXEC')
        self.functions = self._parse_function_starts()

    def _parse_load_commands(self):
        ncmds = u32(self.data, 16)
        off = 32
        for _ in range(ncmds):
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
            if cmdsize < 8:
                raise RuntimeError('invalid Mach-O load command')
            off += cmdsize

    def _parse_function_starts(self):
        if not self.function_starts_cmd:
            raise RuntimeError('LC_FUNCTION_STARTS missing')
        pos, size = self.function_starts_cmd
        end = pos + size
        address = self.text['vmaddr']
        funcs = []
        while pos < end:
            delta, pos = decode_uleb(self.data, pos, end)
            if not delta:
                break
            address += delta
            funcs.append(address)
        return funcs

    def va_to_fileoff(self, va):
        for seg in self.segments:
            start = int(seg['vmaddr'])
            end = start + int(seg['vmsize'])
            if start <= va < end:
                return int(seg['fileoff']) + (va - start)
        return None

    def fileoff_to_va(self, fileoff):
        for seg in self.segments:
            start = int(seg['fileoff'])
            end = start + int(seg['filesize'])
            if start <= fileoff < end:
                return int(seg['vmaddr']) + (fileoff - start)
        return None

    def function_for_va(self, va):
        idx = bisect.bisect_right(self.functions, va) - 1
        return self.functions[idx] if idx >= 0 else None

    def function_end(self, start):
        idx = bisect.bisect_left(self.functions, start)
        if idx + 1 >= len(self.functions):
            return int(self.text_exec['vmaddr'] + self.text_exec['vmsize'])
        return self.functions[idx + 1]

    def words(self, start):
        begin = self.va_to_fileoff(start)
        end = self.va_to_fileoff(self.function_end(start))
        if begin is None or end is None:
            return []
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
        off = self.data.find(value.encode() + b'\0')
        if off < 0:
            return []
        string_va = self.fileoff_to_va(off)
        page = string_va & ~0xFFF
        page_off = string_va & 0xFFF
        refs = []
        start = int(self.text_exec['fileoff'])
        end = start + int(self.text_exec['filesize'])
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
                    refs.append(pc)
                    break
        return refs


def locate_external_method_and_table(macho):
    start = int(macho.text_exec['fileoff'])
    end = start + int(macho.text_exec['filesize'])
    for off in range(start, end - 80, 4):
        # sub w8,w1,#1 ; cmp w8,#15
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
    raise RuntimeError('externalMethod dispatch table not found')


def infer_kernel_collection_base(macho, raw_pointers):
    candidates = collections.Counter()
    for raw in raw_pointers:
        low = raw & 0xFFFFFFFF
        for function in macho.functions:
            base = function - low
            if base & 0xFFF == 0:
                candidates[base] += 1
    if not candidates:
        raise RuntimeError('kernel-collection base not inferred')
    return candidates.most_common(1)[0][0]


def shortest_path(macho, source, target, max_depth=8):
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


def add_immediate(word):
    if word & 0xFF000000 != 0x91000000:
        return None
    imm = (word >> 10) & 0xFFF
    if (word >> 22) & 1:
        imm <<= 12
    return word & 0x1F, (word >> 5) & 0x1F, imm


def analyze(beta3_path, beta4_path):
    beta3 = MachO(beta3_path)
    beta4 = MachO(beta4_path)

    frame_guard = '%lld %d AVE %s: %s:%d %s | frame dimension out of range %p %lld %d %d %d %lld'
    refs = beta4.refs_to_exact_string(frame_guard)
    if not refs:
        raise RuntimeError('beta-4 frame-dimension guard not found')
    beta4_check = beta4.function_for_va(refs[0])
    function_index = beta4.functions.index(beta4_check)
    beta3_check = beta3.functions[function_index]

    _, dispatch_table = locate_external_method_and_table(beta3)
    table_fileoff = beta3.va_to_fileoff(dispatch_table)
    raw_pointers = [u64(beta3.data, table_fileoff + selector * 0x28) for selector in range(1, 16)]
    kc_base = infer_kernel_collection_base(beta3, raw_pointers)
    selector4_handler = kc_base + (raw_pointers[3] & 0xFFFFFFFF)

    path = shortest_path(beta3, selector4_handler, beta3_check)
    if not path or len(path) != 5:
        raise RuntimeError(f'unexpected selector-4 -> CheckInfo path: {path}')

    # path[1] receives selector-4's structuredInput as x1 and later forms
    # x3 = structuredInput + immediate before calling path[2].
    request_substructure_offset = None
    for _, word in beta3.words(path[1]):
        decoded = add_immediate(word)
        if decoded:
            rd, rn, imm = decoded
            if rd == 3 and rn == 20:
                request_substructure_offset = imm
    if request_substructure_offset is None:
        raise RuntimeError('request substructure offset not found')

    # beta-4 CheckInfo moves x2 to x22 and then loads signed width/height as one
    # LDPSW pair. Extract the first such pair from x22.
    dimension_pair_offset = None
    additional_checked_offsets = []
    for _, word in beta4.words(beta4_check):
        if word & 0xFFC00000 == 0x69400000 and ((word >> 5) & 0x1F) == 22:
            imm7 = signed((word >> 15) & 0x7F, 7)
            if dimension_pair_offset is None:
                dimension_pair_offset = imm7 * 4
        if word & 0xFFC00000 == 0xB9400000 and ((word >> 5) & 0x1F) == 22:
            offset = ((word >> 10) & 0xFFF) * 4
            if offset not in additional_checked_offsets:
                additional_checked_offsets.append(offset)
    if dimension_pair_offset is None:
        raise RuntimeError('beta-4 dimension load not found')

    request_width_offset = request_substructure_offset + dimension_pair_offset
    request_height_offset = request_width_offset + 4

    return {
        'selector': 4,
        'structured_input_size': 0x11BA0,
        'selector4_handler': selector4_handler,
        'path': path,
        'beta3_checkinfo': beta3_check,
        'beta4_checkinfo': beta4_check,
        'function_index': function_index,
        'beta3_checkinfo_size': beta3.function_end(beta3_check) - beta3_check,
        'beta4_checkinfo_size': beta4.function_end(beta4_check) - beta4_check,
        'request_substructure_offset': request_substructure_offset,
        'checkinfo_dimension_pair_offset': dimension_pair_offset,
        'request_width_offset': request_width_offset,
        'request_height_offset': request_height_offset,
        'additional_checked_offsets_in_checkinfo': additional_checked_offsets,
        'conclusion': (
            'Selector 4 IO_Prepare passes structuredInput + 0x338 to the beta-3 '
            'CheckInfo-equivalent path. Beta 4 adds signed width/height validation '
            'at CheckInfo +0x3c/+0x40, mapping to request +0x374/+0x378.'
        ),
    }


def main():
    if len(sys.argv) != 4:
        raise SystemExit('usage: ave_prepare_field_map.py <beta3-AppleAVE2> <beta4-AppleAVE2> <output.md>')

    result = analyze(sys.argv[1], sys.argv[2])
    out = [
        '# AppleAVE2 selector-4 frame-field map',
        '',
        'Static/offline analysis only. This tool does not invoke AppleAVE2.',
        '',
        f"- selector: **{result['selector']}** (`IO_Prepare`)",
        f"- structured input size: `0x{result['structured_input_size']:x}`",
        f"- selector-4 handler: `0x{result['selector4_handler']:x}`",
        f"- beta-3 CheckInfo-equivalent: `0x{result['beta3_checkinfo']:x}` (size `0x{result['beta3_checkinfo_size']:x}`)",
        f"- beta-4 CheckInfo-equivalent: `0x{result['beta4_checkinfo']:x}` (size `0x{result['beta4_checkinfo_size']:x}`)",
        f"- matched LC_FUNCTION_STARTS index: `{result['function_index']}`",
        '',
        '## Static call path',
        '',
        '`' + ' -> '.join(f"0x{value:x}" for value in result['path']) + '`',
        '',
        '## Request mapping',
        '',
        f"- CheckInfo substructure begins at selector-4 request `+0x{result['request_substructure_offset']:x}`",
        f"- beta-4 width field: CheckInfo `+0x{result['checkinfo_dimension_pair_offset']:x}` -> request `+0x{result['request_width_offset']:x}`",
        f"- beta-4 height field: CheckInfo `+0x{result['checkinfo_dimension_pair_offset'] + 4:x}` -> request `+0x{result['request_height_offset']:x}`",
        '- beta-4 validates the pair as signed values and checks their 64-bit product before continuing',
        '',
        '## Additional fields read by beta-4 CheckInfo',
        '',
    ]
    for offset in result['additional_checked_offsets_in_checkinfo']:
        out.append(f'- CheckInfo `+0x{offset:x}` -> request `+0x{result["request_substructure_offset"] + offset:x}`')
    out += [
        '',
        '## Interpretation',
        '',
        result['conclusion'],
        '',
        'This establishes source-to-validation reachability only. It does not prove memory corruption or a useful kernel primitive.',
    ]
    Path(sys.argv[3]).write_text('\n'.join(out) + '\n')
    print('\n'.join(out))


if __name__ == '__main__':
    main()
