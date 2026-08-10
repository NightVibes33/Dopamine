#!/usr/bin/env python3
"""Offline AppleAVE2 selector-4 dimension-flow validator.

Static analysis only. It never opens IOKit or modifies firmware.
"""
import bisect
import collections
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
        self.data = Path(path).read_bytes()
        self.segments = []
        self.function_starts_cmd = None
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
                return seg['fileoff'] + (va - seg['vmaddr'])
        return None

    def fileoff_to_va(self, fileoff):
        for seg in self.segments:
            if seg['fileoff'] <= fileoff < seg['fileoff'] + seg['filesize']:
                return seg['vmaddr'] + (fileoff - seg['fileoff'])
        return None

    def function_for_va(self, va):
        index = bisect.bisect_right(self.functions, va) - 1
        return self.functions[index] if index >= 0 else None

    def function_end(self, start):
        index = bisect.bisect_left(self.functions, start)
        if index + 1 < len(self.functions):
            return self.functions[index + 1]
        return self.text_exec['vmaddr'] + self.text_exec['vmsize']

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


def locate_dispatch_table(macho):
    start = macho.text_exec['fileoff']
    end = start + macho.text_exec['filesize']
    for off in range(start, end - 80, 4):
        if u32(macho.data, off) != 0x51000428 or u32(macho.data, off + 4) != 0x71003D1F:
            continue
        for pos in range(off + 8, off + 80, 4):
            word = u32(macho.data, pos)
            if word & 0x9F000000 != 0x90000000 or (word & 31) != 3:
                continue
            pc = macho.fileoff_to_va(pos)
            page = decode_adrp(word, pc)
            nxt = u32(macho.data, pos + 4)
            if nxt & 0x7F000000 == 0x11000000 and (nxt & 31) == 3 and ((nxt >> 5) & 31) == 3:
                imm = (nxt >> 10) & 0xFFF
                if (nxt >> 22) & 1:
                    imm <<= 12
                return page + imm
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


def mov_reg(word):
    if word & 0xFFE0FFE0 == 0xAA0003E0:
        return word & 31, (word >> 16) & 31
    return None


def movz_w(word):
    if word & 0x7F800000 == 0x52800000:
        return word & 31, ((word >> 5) & 0xFFFF) << (((word >> 21) & 3) * 16)
    return None


def add_reg_x(word):
    if word & 0xFF200000 == 0x8B000000 and ((word >> 10) & 0x3F) == 0:
        return word & 31, (word >> 5) & 31, (word >> 16) & 31
    return None


def ldr_w_uimm(word):
    if word & 0xFFC00000 == 0xB9400000:
        return word & 31, (word >> 5) & 31, ((word >> 10) & 0xFFF) * 4
    return None


def pair_w(word):
    kind = word & 0xFFC00000
    if kind not in (0x29000000, 0x29400000):
        return None
    return (
        'ldp' if kind == 0x29400000 else 'stp',
        word & 31,
        (word >> 10) & 31,
        (word >> 5) & 31,
        signed((word >> 15) & 0x7F, 7) * 4,
    )


def bl_target(pc, word):
    if word & 0xFC000000 != 0x94000000:
        return None
    return (pc + signed(word & 0x03FFFFFF, 26) * 4) & 0xFFFFFFFFFFFFFFFF


def analyze(beta3_path, beta4_path):
    beta3 = MachO(beta3_path)
    beta4 = MachO(beta4_path)

    guard = '%lld %d AVE %s: %s:%d %s | frame dimension out of range %p %lld %d %d %d %lld'
    refs = beta4.refs_to_exact_string(guard)
    if not refs:
        raise RuntimeError('beta-4 frame-dimension guard not found')
    beta4_check = beta4.function_for_va(refs[0])
    function_index = beta4.functions.index(beta4_check)
    beta3_check = beta3.functions[function_index]

    dispatch_table = locate_dispatch_table(beta3)
    table_fileoff = beta3.va_to_fileoff(dispatch_table)
    raw_pointers = [u64(beta3.data, table_fileoff + selector * 0x28) for selector in range(1, 16)]
    kc_base = infer_kernel_collection_base(beta3, raw_pointers)
    selector4 = kc_base + (raw_pointers[3] & 0xFFFFFFFF)

    check_path = shortest_path(beta3, selector4, beta3_check)
    if not check_path or len(check_path) != 5:
        raise RuntimeError(f'unexpected selector-4 CheckInfo path: {check_path}')

    request_substructure = None
    for _, word in beta3.words(check_path[1]):
        if word & 0xFFC00000 == 0x91000000 and (word & 31) == 3 and ((word >> 5) & 31) == 20:
            imm = (word >> 10) & 0xFFF
            if (word >> 22) & 1:
                imm <<= 12
            if imm:
                request_substructure = imm
    if request_substructure is None:
        raise RuntimeError('selector-4 request substructure offset not found')

    dimension_pair = None
    for _, word in beta4.words(beta4_check):
        if word & 0xFFC00000 == 0x69400000 and ((word >> 5) & 31) == 22:
            dimension_pair = signed((word >> 15) & 0x7F, 7) * 4
            break
    if dimension_pair is None:
        raise RuntimeError('beta-4 width/height load not found')

    request_width = request_substructure + dimension_pair
    request_height = request_width + 4

    copy_function = check_path[-2]
    copy_words = beta3.words(copy_function)
    if not any(mov_reg(word) == (20, 0) for _, word in copy_words):
        raise RuntimeError('session register mapping changed')
    if not any(mov_reg(word) == (21, 2) for _, word in copy_words):
        raise RuntimeError('request register mapping changed')

    copy_offset = None
    copy_length = None
    for index, (_, word) in enumerate(copy_words):
        decoded = movz_w(word)
        if not decoded or decoded[0] != 8:
            continue
        candidate_offset = decoded[1]
        window = copy_words[index + 1:index + 7]
        if not any(add_reg_x(value) == (0, 20, 8) for _, value in window):
            continue
        if not any(mov_reg(value) == (1, 21) for _, value in window):
            continue
        for _, value in window:
            candidate_length = movz_w(value)
            if candidate_length and candidate_length[0] == 2:
                copy_length = candidate_length[1]
        if copy_length:
            copy_offset = candidate_offset
            break
    if copy_offset is None:
        raise RuntimeError('request-to-session copy not found')

    session_width = copy_offset + dimension_pair
    session_height = session_width + 4

    diagnostic = '%lld %d AVE %s: %s:%d GBufSize: %d, encType: %d, width: %d, height: %d, chromaFmt: %d, bitDepth: %d, frameRate: %d'
    calc_refs = beta3.refs_to_exact_string(diagnostic)
    if not calc_refs:
        raise RuntimeError('coded-data size calculator diagnostic not found')
    coded_calc = beta3.function_for_va(calc_refs[0])

    chosen = None
    for caller in beta3.functions:
        if coded_calc not in beta3.direct_calls(caller):
            continue
        words = beta3.words(caller)
        spills = []
        for index in range(len(words) - 2):
            first = ldr_w_uimm(words[index][1])
            second = ldr_w_uimm(words[index + 1][1])
            store = pair_w(words[index + 2][1])
            if not first or not second or not store or store[0] != 'stp':
                continue
            reg1, base1, off1 = first
            reg2, base2, off2 = second
            if (off1, off2) != (session_width, session_height) or off2 != off1 + 4:
                continue
            if store[1] == reg1 and store[2] == reg2 and store[3] == 31:
                spills.append((off1, off2, store[4]))
        if not spills:
            continue

        for index, (pc, word) in enumerate(words):
            if bl_target(pc, word) != coded_calc:
                continue
            for _, previous in words[max(0, index - 8):index]:
                load = pair_w(previous)
                if not load or load[0] != 'ldp' or load[1:4] != (3, 4, 31):
                    continue
                for spill in spills:
                    if spill[2] != load[4]:
                        continue
                    path = shortest_path(beta3, selector4, caller)
                    if path:
                        chosen = (caller, spill, path + [coded_calc])
                        break
                if chosen:
                    break
            if chosen:
                break
        if chosen:
            break

    if not chosen:
        raise RuntimeError('copied frame dimensions are not proven to reach coded-data sizing')

    caller, spill, coded_path = chosen
    calc_width, calc_height, stack_slot = spill
    if (calc_width, calc_height) != (session_width, session_height):
        raise RuntimeError('dimension propagation mismatch')

    return {
        'selector4': selector4,
        'request_substructure': request_substructure,
        'request_width': request_width,
        'request_height': request_height,
        'session_copy_function': copy_function,
        'session_copy_offset': copy_offset,
        'session_copy_length': copy_length,
        'session_width': session_width,
        'session_height': session_height,
        'coded_calc': coded_calc,
        'coded_caller': caller,
        'coded_path': coded_path,
        'calc_width_session': calc_width,
        'calc_height_session': calc_height,
        'stack_slot': stack_slot,
    }


def main():
    if len(sys.argv) != 4:
        raise SystemExit('usage: ave_dimension_flow_map.py <beta3-AppleAVE2> <beta4-AppleAVE2> <output.md>')
    result = analyze(sys.argv[1], sys.argv[2])
    out = [
        '# AppleAVE2 selector-4 dimension flow',
        '',
        'Static/offline validation only; no IOKit calls or firmware modification.',
        '',
        f"- selector 4 handler: `0x{result['selector4']:x}`",
        f"- request substructure: `+0x{result['request_substructure']:x}`",
        f"- request width/height: `+0x{result['request_width']:x}` / `+0x{result['request_height']:x}`",
        f"- session copy: function `0x{result['session_copy_function']:x}`, destination `+0x{result['session_copy_offset']:x}`, length `0x{result['session_copy_length']:x}`",
        f"- session width/height after copy: `+0x{result['session_width']:x}` / `+0x{result['session_height']:x}`",
        f"- coded-data calculator: `0x{result['coded_calc']:x}`",
        f"- calculator caller: `0x{result['coded_caller']:x}`",
        f"- width/height are loaded from session `+0x{result['calc_width_session']:x}` / `+0x{result['calc_height_session']:x}` and passed as calculator arguments 3/4",
        '',
        '## Call path to coded-data sizing',
        '',
        '`' + ' -> '.join(f"0x{value:x}" for value in result['coded_path']) + '`',
        '',
        '## Conclusion',
        '',
        'The selector-4 request frame dimensions that beta 4 newly validates are copied unchanged into the session object and later passed as the width/height arguments to the coded-data buffer-size calculation on beta 3.',
        '',
        'This proves static source-to-sizing propagation. It does not prove memory corruption or a useful kernel primitive.',
    ]
    Path(sys.argv[3]).write_text('\n'.join(out) + '\n')
    print('\n'.join(out))


if __name__ == '__main__':
    main()
