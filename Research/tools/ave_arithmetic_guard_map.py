#!/usr/bin/env python3
"""Compare beta3/beta4 AppleAVE2 coded-data dimension arithmetic.

Static/offline only. This intentionally does not generate trigger values.
"""
import bisect
import struct
import sys
from pathlib import Path

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

    def fileoff_to_va(self, fileoff):
        for seg in self.segments:
            if seg['fileoff'] <= fileoff < seg['fileoff'] + seg['filesize']:
                return seg['vmaddr'] + fileoff - seg['fileoff']
        return None

    def va_to_fileoff(self, va):
        for seg in self.segments:
            if seg['vmaddr'] <= va < seg['vmaddr'] + seg['vmsize']:
                return seg['fileoff'] + va - seg['vmaddr']
        return None

    def function_for_va(self, va):
        idx = bisect.bisect_right(self.functions, va) - 1
        return self.functions[idx] if idx >= 0 else None

    def function_end(self, start):
        idx = bisect.bisect_left(self.functions, start)
        return self.functions[idx + 1]

    def refs_to_exact_string(self, value):
        off = self.data.find(value.encode() + b'\0')
        if off < 0:
            return []
        va = self.fileoff_to_va(off)
        page = va & ~0xFFF
        page_off = va & 0xFFF
        refs = []
        for fileoff in range(self.text_exec['fileoff'], self.text_exec['fileoff'] + self.text_exec['filesize'] - 24, 4):
            word = u32(self.data, fileoff)
            if word & 0x9F000000 != 0x90000000:
                continue
            pc = self.fileoff_to_va(fileoff)
            if decode_adrp(word, pc) != page:
                continue
            reg = word & 31
            for delta in range(4, 24, 4):
                nxt = u32(self.data, fileoff + delta)
                if nxt & 0x7F000000 != 0x11000000 or ((nxt >> 5) & 31) != reg:
                    continue
                imm = (nxt >> 10) & 0xFFF
                if (nxt >> 22) & 1:
                    imm <<= 12
                if imm == page_off:
                    refs.append(pc)
                    break
        return refs

    def words(self, start, limit=None):
        begin = self.va_to_fileoff(start)
        end = self.va_to_fileoff(self.function_end(start))
        if limit:
            end = min(end, begin + limit)
        return [(self.fileoff_to_va(off), u32(self.data, off)) for off in range(begin, end, 4)]


def smull_regs(word):
    if word & 0xFFE08000 == 0x9B200000 and ((word >> 10) & 31) == 31:
        return word & 31, (word >> 5) & 31, (word >> 16) & 31
    return None


def mul_w_regs(word):
    if word & 0xFFE08000 == 0x1B000000 and ((word >> 10) & 31) == 31:
        return word & 31, (word >> 5) & 31, (word >> 16) & 31
    return None


def is_lsr_x_31(word):
    return (word & 0xFFC0FC00) == 0xD340FC00 and ((word >> 16) & 0x3F) == 31


def is_cbnz_x(word):
    return word & 0x7F000000 == 0x35000000 and ((word >> 31) & 1) == 1


def analyze(beta3_path, beta4_path):
    diagnostic = '%lld %d AVE %s: %s:%d GBufSize: %d, encType: %d, width: %d, height: %d, chromaFmt: %d, bitDepth: %d, frameRate: %d'
    beta3 = MachO(beta3_path)
    beta4 = MachO(beta4_path)
    beta3_calc = beta3.function_for_va(beta3.refs_to_exact_string(diagnostic)[0])
    beta4_calc = beta4.function_for_va(beta4.refs_to_exact_string(diagnostic)[0])

    beta3_words = beta3.words(beta3_calc, 0x120)
    beta4_words = beta4.words(beta4_calc, 0x120)

    guard = None
    for index, (pc, word) in enumerate(beta4_words[:-2]):
        multiply = smull_regs(word)
        if not multiply or set(multiply[1:]) != {3, 4}:
            continue
        for pos in range(index + 1, min(index + 6, len(beta4_words) - 1)):
            if is_lsr_x_31(beta4_words[pos][1]) and is_cbnz_x(beta4_words[pos + 1][1]):
                guard = (pc, beta4_words[pos][0], beta4_words[pos + 1][0])
                break
        if guard:
            break
    if guard is None:
        raise RuntimeError('beta4 64-bit width/height product guard not found')

    if any(smull_regs(word) and set(smull_regs(word)[1:]) == {3, 4} for _, word in beta3_words):
        raise RuntimeError('beta3 unexpectedly contains beta4-style wide product guard')

    beta3_multiply = None
    for pc, word in beta3.words(beta3_calc, 0xC0):
        if mul_w_regs(word):
            beta3_multiply = pc
            break
    if beta3_multiply is None:
        raise RuntimeError('beta3 early 32-bit sizing multiply not found')

    return {
        'beta3_calc': beta3_calc,
        'beta4_calc': beta4_calc,
        'beta3_multiply': beta3_multiply,
        'beta4_wide_multiply': guard[0],
        'beta4_range_branch': guard[2],
    }


def main():
    if len(sys.argv) != 4:
        raise SystemExit('usage: ave_arithmetic_guard_map.py <beta3-AppleAVE2> <beta4-AppleAVE2> <output.md>')
    result = analyze(sys.argv[1], sys.argv[2])
    out = [
        '# AppleAVE2 coded-data arithmetic hardening',
        '',
        'Static/offline comparison only. No trigger values are generated.',
        '',
        f"- beta3 coded-data calculator: `0x{result['beta3_calc']:x}`",
        f"- beta4 coded-data calculator: `0x{result['beta4_calc']:x}`",
        f"- beta3 reaches a 32-bit multiply in the early sizing path at `0x{result['beta3_multiply']:x}` without the beta4 product-range guard",
        f"- beta4 adds a signed 64-bit width×height multiply at `0x{result['beta4_wide_multiply']:x}` and a rejecting range branch at `0x{result['beta4_range_branch']:x}`",
        '',
        '## Conclusion',
        '',
        'Beta 4 adds an explicit wide-product range check before coded-data sizing continues. The corresponding beta-3 calculator lacks that guard and reaches narrower dimension arithmetic directly. Combined with the separately proven selector-4 field flow and allocation sink, this is consistent with an integer-overflow/undersized-allocation risk in the pre-hardening path.',
        '',
        'This does not demonstrate corruption and intentionally does not derive a triggering width/height pair.',
    ]
    Path(sys.argv[3]).write_text('\n'.join(out) + '\n')
    print('\n'.join(out))


if __name__ == '__main__':
    main()
