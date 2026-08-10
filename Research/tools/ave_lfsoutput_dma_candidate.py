#!/usr/bin/env python3
"""Offline AppleAVE2 LFSOutput host-allocation -> firmware write-DMA validator.

Static analysis only. It does not open IOKit, invoke AppleAVE2, derive a
triggering frame size, or modify firmware/device state.
"""
from __future__ import annotations

import bisect
import struct
import sys
from pathlib import Path

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_FUNCTION_STARTS = 0x26
N_TYPE = 0x0E
N_SECT = 0x0E


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


def bl_target(pc, word):
    if word & 0xFC000000 != 0x94000000:
        return None
    return (pc + (signed(word & 0x03FFFFFF, 26) << 2)) & 0xFFFFFFFFFFFFFFFF


def ldr_w_uimm(word):
    if word & 0xFFC00000 == 0xB9400000:
        return word & 31, (word >> 5) & 31, ((word >> 10) & 0xFFF) * 4
    return None


def ldr_x_uimm(word):
    if word & 0xFFC00000 == 0xF9400000:
        return word & 31, (word >> 5) & 31, ((word >> 10) & 0xFFF) * 8
    return None


def str_w_uimm(word):
    if word & 0xFFC00000 == 0xB9000000:
        return word & 31, (word >> 5) & 31, ((word >> 10) & 0xFFF) * 4
    return None


def str_x_uimm(word):
    if word & 0xFFC00000 == 0xF9000000:
        return word & 31, (word >> 5) & 31, ((word >> 10) & 0xFFF) * 8
    return None


def mov_x(word):
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


def ldp_w(word):
    if word & 0xFFC00000 == 0x29400000:
        return word & 31, (word >> 10) & 31, (word >> 5) & 31, signed((word >> 15) & 0x7F, 7) * 4
    return None


def madd_w(word):
    if word & 0x7FE00000 == 0x1B000000:
        return word & 31, (word >> 5) & 31, (word >> 16) & 31, (word >> 10) & 31
    return None


class KextMachO:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self.segments = []
        function_starts = None
        off = 32
        for _ in range(u32(self.data, 16)):
            cmd = u32(self.data, off)
            cmdsize = u32(self.data, off + 4)
            if cmd == LC_SEGMENT_64:
                name = self.data[off + 8:off + 24].split(b'\0')[0].decode(errors='replace')
                self.segments.append({
                    'name': name, 'vmaddr': u64(self.data, off + 24),
                    'vmsize': u64(self.data, off + 32), 'fileoff': u64(self.data, off + 40),
                    'filesize': u64(self.data, off + 48),
                })
            elif cmd == LC_FUNCTION_STARTS:
                function_starts = (u32(self.data, off + 8), u32(self.data, off + 12))
            if cmdsize < 8:
                raise RuntimeError('invalid load command')
            off += cmdsize
        if function_starts is None:
            raise RuntimeError('KEXT LC_FUNCTION_STARTS missing')
        self.text = next(s for s in self.segments if s['name'] == '__TEXT')
        self.text_exec = next(s for s in self.segments if s['name'] == '__TEXT_EXEC')
        pos, size = function_starts
        end = pos + size
        address = self.text['vmaddr']
        self.functions = []
        while pos < end:
            delta, pos = decode_uleb(self.data, pos, end)
            if not delta:
                break
            address += delta
            self.functions.append(address)
        self.function_set = set(self.functions)

    def va_to_fileoff(self, va):
        for s in self.segments:
            if s['vmaddr'] <= va < s['vmaddr'] + s['vmsize']:
                return s['fileoff'] + va - s['vmaddr']
        return None

    def fileoff_to_va(self, fileoff):
        for s in self.segments:
            if s['fileoff'] <= fileoff < s['fileoff'] + s['filesize']:
                return s['vmaddr'] + fileoff - s['fileoff']
        return None

    def function_for_va(self, va):
        i = bisect.bisect_right(self.functions, va) - 1
        return (i, self.functions[i]) if i >= 0 else (None, None)

    def function_end(self, start):
        i = bisect.bisect_left(self.functions, start)
        if i + 1 < len(self.functions):
            return self.functions[i + 1]
        return self.text_exec['vmaddr'] + self.text_exec['vmsize']

    def function_size(self, start):
        return self.function_end(start) - start

    def words(self, start):
        begin = self.va_to_fileoff(start)
        end = self.va_to_fileoff(self.function_end(start))
        if begin is None or end is None:
            return []
        return [(self.fileoff_to_va(off), u32(self.data, off)) for off in range(begin, end, 4)]

    def exact_strings_containing(self, marker):
        needle = marker.encode()
        found = {}
        pos = 0
        while True:
            hit = self.data.find(needle, pos)
            if hit < 0:
                break
            start = self.data.rfind(b'\0', 0, hit) + 1
            end = self.data.find(b'\0', hit)
            if end < 0:
                break
            try:
                value = self.data[start:end].decode()
            except UnicodeDecodeError:
                value = ''
            if marker in value:
                va = self.fileoff_to_va(start)
                if va is not None:
                    found[va] = value
            pos = hit + len(needle)
        return list(found.items())

    def xrefs_to_va(self, target_va):
        page = target_va & ~0xFFF
        page_off = target_va & 0xFFF
        refs = []
        begin = self.text_exec['fileoff']
        end = begin + self.text_exec['filesize']
        for fileoff in range(begin, end - 24, 4):
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

    def functions_referencing_marker(self, marker):
        out = set()
        for va, _ in self.exact_strings_containing(marker):
            for ref in self.xrefs_to_va(va):
                index, function = self.function_for_va(ref)
                if function is not None:
                    out.add((index, function))
        return sorted(out)


class PreloadMachO:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self.segments = []
        self.sections = [None]
        symtab = None
        off = 32
        for _ in range(u32(self.data, 16)):
            cmd = u32(self.data, off)
            cmdsize = u32(self.data, off + 4)
            if cmd == LC_SEGMENT_64:
                segname = self.data[off + 8:off + 24].split(b'\0')[0].decode(errors='replace')
                self.segments.append({
                    'name': segname, 'vmaddr': u64(self.data, off + 24),
                    'vmsize': u64(self.data, off + 32), 'fileoff': u64(self.data, off + 40),
                    'filesize': u64(self.data, off + 48),
                })
                nsects = u32(self.data, off + 64)
                sectoff = off + 72
                for _sect in range(nsects):
                    sectname = self.data[sectoff:sectoff+16].split(b'\0')[0].decode(errors='replace')
                    secseg = self.data[sectoff+16:sectoff+32].split(b'\0')[0].decode(errors='replace')
                    self.sections.append({
                        'sectname': sectname, 'segname': secseg,
                        'addr': u64(self.data, sectoff + 32), 'size': u64(self.data, sectoff + 40),
                        'offset': u32(self.data, sectoff + 48),
                    })
                    sectoff += 80
            elif cmd == LC_SYMTAB:
                symtab = (u32(self.data, off + 8), u32(self.data, off + 12),
                          u32(self.data, off + 16), u32(self.data, off + 20))
            if cmdsize < 8:
                raise RuntimeError('invalid PRELOAD load command')
            off += cmdsize
        if symtab is None:
            raise RuntimeError('PRELOAD LC_SYMTAB missing')
        symoff, nsyms, stroff, strsize = symtab
        strings = self.data[stroff:stroff+strsize]
        symbols = []
        for i in range(nsyms):
            noff = symoff + i * 16
            strx = u32(self.data, noff)
            n_type = self.data[noff + 4]
            n_sect = self.data[noff + 5]
            value = u64(self.data, noff + 8)
            if strx >= len(strings) or n_sect == 0 or n_sect >= len(self.sections):
                continue
            end = strings.find(b'\0', strx)
            if end < 0:
                continue
            name = strings[strx:end].decode(errors='replace')
            sec = self.sections[n_sect]
            if (n_type & N_TYPE) == N_SECT and sec and sec['segname'] == '__TEXT' and sec['sectname'] == '__text' and value:
                symbols.append((value, name))
        self.symbols = sorted(set(symbols))
        self.symbol_values = [v for v, _ in self.symbols]

    def va_to_fileoff(self, va):
        for s in self.segments:
            if s['vmaddr'] <= va < s['vmaddr'] + s['vmsize']:
                return s['fileoff'] + va - s['vmaddr']
        return None

    def symbol_containing(self, marker):
        matches = [(v, n) for v, n in self.symbols if marker in n]
        if len(matches) != 1:
            raise RuntimeError(f'{marker}: expected one text symbol, got {matches[:8]}')
        return matches[0]

    def symbol_end(self, start):
        i = bisect.bisect_right(self.symbol_values, start)
        if i >= len(self.symbol_values):
            sec = next(s for s in self.sections if s and s['segname'] == '__TEXT' and s['sectname'] == '__text')
            return sec['addr'] + sec['size']
        return self.symbol_values[i]

    def words(self, start):
        end = self.symbol_end(start)
        begin_off = self.va_to_fileoff(start)
        end_off = self.va_to_fileoff(end)
        if begin_off is None or end_off is None:
            raise RuntimeError('firmware symbol not file-backed')
        return [(start + (off - begin_off), u32(self.data, off)) for off in range(begin_off, end_off, 4)]


def find_lfs_calc(beta3, beta4):
    b4_matches = beta4.functions_referencing_marker('AVE_CalcBufSizeOfLFSOutput')
    if len(b4_matches) != 1:
        raise RuntimeError(f'beta4 LFS calculator ambiguous: {b4_matches}')
    index, b4_func = b4_matches[0]
    if index >= len(beta3.functions):
        raise RuntimeError('LFS function index absent in beta3')
    b3_func = beta3.functions[index]
    guard_funcs = {f for _, f in beta4.functions_referencing_marker('size >= 0 && size <= 2147483647')}
    if b4_func not in guard_funcs:
        raise RuntimeError('beta4 LFS calculator lacks wide-size guard xref')
    if b3_func in {f for _, f in beta3.functions_referencing_marker('size >= 0 && size <= 2147483647')}:
        raise RuntimeError('beta3 unexpectedly has beta4 LFS wide-size guard')
    return index, b3_func, b4_func


def find_result_slot(macho, calc):
    rows = []
    for function in macho.functions:
        words = macho.words(function)
        for i, (pc, word) in enumerate(words[:-1]):
            if bl_target(pc, word) != calc:
                continue
            store = str_w_uimm(words[i+1][1])
            if store and store[0] == 0:
                rows.append((function, pc, store[1], store[2]))
    slots = {row[3] for row in rows}
    if slots != {0x37C}:
        raise RuntimeError(f'LFS result slot mismatch: {rows[:8]}')
    return rows


def find_allocation_consumer(macho, slot):
    candidates = []
    for index, function in enumerate(macho.functions):
        words = macho.words(function)
        for i, (pc, word) in enumerate(words):
            load = ldr_w_uimm(word)
            if not load or load[2] != slot:
                continue
            size_reg = load[0]
            for j in range(i+1, min(i+90, len(words))):
                if mov_x(words[j][1]) != (4, size_reg):
                    continue
                for k in range(j+1, min(j+6, len(words))):
                    target = bl_target(words[k][0], words[k][1])
                    if target in macho.function_set:
                        candidates.append((index, function, pc, words[j][0], words[k][0], target))
                        break
                if candidates:
                    break
    if not candidates:
        raise RuntimeError('no LFS allocation consumer found')
    return candidates[0], candidates


def find_serializer(macho, marker, expected_info_offset):
    funcs = macho.functions_referencing_marker(marker)
    if not funcs:
        raise RuntimeError('LFS pInfo assertion function not found')
    candidates = []
    for index, function in funcs:
        words = macho.words(function)
        for i, (_, word) in enumerate(words):
            mov = movz_w(word)
            if not mov or mov[1] != expected_info_offset:
                continue
            offset_reg = mov[0]
            for j in range(i+1, min(i+5, len(words))):
                add = add_reg_x(words[j][1])
                if not add or add[0] != 3 or add[2] != offset_reg:
                    continue
                for k in range(j+1, min(j+6, len(words))):
                    target = bl_target(words[k][0], words[k][1])
                    if target in macho.function_set:
                        candidates.append((index, function, expected_info_offset, words[k][0], target))
                        break
    filtered = []
    for row in candidates:
        _, function, info_offset, call_pc, _target = row
        words = macho.words(function)
        call_index = next(i for i, (pc, _) in enumerate(words) if pc == call_pc)
        if any((load := ldr_x_uimm(next_word)) and load[2] == info_offset for _, next_word in words[call_index+1:call_index+4]):
            filtered.append(row)
    if not filtered:
        raise RuntimeError(f'LFS serializer offset +0x{expected_info_offset:x} not found')
    helper_targets = {r[4] for r in filtered}
    if len(helper_targets) != 1:
        raise RuntimeError(f'LFS serializer helper ambiguous: {filtered}')
    return filtered[0], filtered


def validate_descriptor_helper(macho, helper):
    words = macho.words(helper)
    size_transfer = None
    address_store = None
    for i, (pc, word) in enumerate(words):
        load = ldr_w_uimm(word)
        if load and load[2] == 0x100:
            reg = load[0]
            for pc2, word2 in words[i+1:i+7]:
                store = str_w_uimm(word2)
                if store and store[0] == reg and store[2] == 8:
                    size_transfer = (pc, pc2, load[1], store[1])
                    break
        storex = str_x_uimm(word)
        if storex and storex[2] == 0:
            address_store = pc
    if size_transfer is None or address_store is None:
        raise RuntimeError('generic descriptor helper does not prove {address,size} export')
    return size_transfer, address_store


def analyze_firmware(path, expected_info_offset):
    fw = PreloadMachO(path)
    start, symbol = fw.symbol_containing('ConfigWrDMALowResFSRslts')
    end = fw.symbol_end(start)
    words = fw.words(start)
    address_loads = []
    size_loads = []
    geometry_loads = []
    madds = []
    stores = []
    for pc, word in words:
        lx = ldr_x_uimm(word)
        if lx and lx[1] == 1:
            if lx[2] == expected_info_offset:
                address_loads.append((pc, lx))
            if lx[2] == expected_info_offset + 8:
                size_loads.append((pc, lx))
        lw = ldr_w_uimm(word)
        if lw and lw[1] == 1 and lw[2] == expected_info_offset + 8:
            size_loads.append((pc, lw))
        pair = ldp_w(word)
        if pair and pair[2] == 0 and pair[3] == 0x18:
            geometry_loads.append((pc, pair))
        if madd_w(word):
            madds.append(pc)
        if str_w_uimm(word):
            stores.append(pc)
    if not address_loads:
        raise RuntimeError(f'{symbol}: LFS address offset +0x{expected_info_offset:x} not loaded')
    if size_loads:
        raise RuntimeError(f'{symbol}: adjacent backing-size field unexpectedly loaded: {size_loads}')
    if not geometry_loads:
        raise RuntimeError(f'{symbol}: geometry load from PICMGMT +0x18 not found')
    if len(madds) < 2:
        raise RuntimeError(f'{symbol}: expected geometry-derived multiply-add extent calculations')
    if len(stores) < 4:
        raise RuntimeError(f'{symbol}: insufficient write-register stores for DMA setup')
    return {
        'symbol': symbol, 'start': start, 'end': end, 'size': end-start,
        'address_load': address_loads[0][0], 'geometry_load': geometry_loads[0][0],
        'madd_count': len(madds), 'store_count': len(stores),
    }


def analyze(k3_path, k4_path, fw3_path, fw4_path):
    b3 = KextMachO(k3_path)
    b4 = KextMachO(k4_path)
    index, calc3, calc4 = find_lfs_calc(b3, b4)
    stores3 = find_result_slot(b3, calc3)
    stores4 = find_result_slot(b4, calc4)
    alloc3, all_alloc3 = find_allocation_consumer(b3, 0x37C)
    alloc4, all_alloc4 = find_allocation_consumer(b4, 0x37C)
    ser3, _ = find_serializer(b3, 'pInfo->sBufPFSet.sLFSOutput.iAddr != 0', 0x51B0)
    ser4, _ = find_serializer(b4, 'pInfo->sBufPFSet.sLFSOutput.iAddr != 0', 0x51C8)
    helper3 = validate_descriptor_helper(b3, ser3[4])
    helper4 = validate_descriptor_helper(b4, ser4[4])
    fw3 = analyze_firmware(fw3_path, ser3[2])
    fw4 = analyze_firmware(fw4_path, ser4[2])
    if fw3['size'] != fw4['size']:
        raise RuntimeError(f'LFS firmware DMA routine size changed: 0x{fw3["size"]:x} -> 0x{fw4["size"]:x}')
    return {
        'calc_index': index, 'calc3': calc3, 'calc4': calc4,
        'calc3_size': b3.function_size(calc3), 'calc4_size': b4.function_size(calc4),
        'result_stores3': stores3, 'result_stores4': stores4,
        'alloc3': alloc3, 'alloc4': alloc4, 'alloc_count3': len(all_alloc3), 'alloc_count4': len(all_alloc4),
        'serializer3': ser3, 'serializer4': ser4, 'helper3': helper3, 'helper4': helper4,
        'fw3': fw3, 'fw4': fw4,
    }


def main():
    if len(sys.argv) != 6:
        raise SystemExit('usage: ave_lfsoutput_dma_candidate.py <b3-kext> <b4-kext> <b3-fw> <b4-fw> <output.md>')
    result = analyze(*sys.argv[1:5])
    out = [
        '# AppleAVE2 LFSOutput host-allocation -> H17 write-DMA candidate', '',
        'Static/offline validation only. No AppleAVE2 selector is invoked, no device state is modified, and no triggering frame dimensions are derived.', '',
        '## Host sizing hardening', '',
        f"- `AVE_CalcBufSizeOfLFSOutput` maps to LC_FUNCTION_STARTS index `{result['calc_index']}` on both builds",
        f"- beta3 calculator: `0x{result['calc3']:x}` size `0x{result['calc3_size']:x}`",
        f"- beta4 calculator: `0x{result['calc4']:x}` size `0x{result['calc4_size']:x}`",
        '- beta4 calculator references the signed-31-bit size guard; beta3 counterpart does not',
        '- both calculators return into buffer-size descriptor `+0x37c`', '',
        '## Host surface allocation', '',
        f"- beta3 allocation consumer: function `0x{result['alloc3'][1]:x}` (index `{result['alloc3'][0]}`), loads `+0x37c` at `0x{result['alloc3'][2]:x}` and passes that register as `x4` at `0x{result['alloc3'][3]:x}` to create/replacement call `0x{result['alloc3'][5]:x}`",
        f"- beta4 has an equivalent `+0x37c` -> `x4` surface-allocation pattern (function index `{result['alloc4'][0]}`)", '',
        '## Kernel -> firmware descriptor', '',
        f"- beta3 LFS pInfo descriptor offset: `+0x{result['serializer3'][2]:x}`",
        f"- beta4 LFS pInfo descriptor offset: `+0x{result['serializer4'][2]:x}`",
        '- the generic descriptor helper writes mapped/DART address at descriptor `+0x0` and actual backing-surface size at descriptor `+0x8`', '',
        '## H17 write-DMA consumer', '',
        f"- beta3 `{result['fw3']['symbol']}`: `0x{result['fw3']['start']:x}` size `0x{result['fw3']['size']:x}`",
        f"- beta4 counterpart: `0x{result['fw4']['start']:x}` size `0x{result['fw4']['size']:x}`",
        f"- beta3 firmware loads LFS destination address from pInfo `+0x{result['serializer3'][2]:x}` at `0x{result['fw3']['address_load']:x}`",
        f"- beta4 loads the shifted address field from pInfo `+0x{result['serializer4'][2]:x}`",
        '- neither firmware routine loads the adjacent serialized backing-size field (`descriptor +0x8`)',
        '- both routines load frame geometry and contain multiply-add arithmetic used to derive DMA extents before programming write-DMA registers',
        '- the firmware routine has identical size across beta3 and beta4; the relevant beta4 hardening is upstream in the host size calculator', '',
        '## Assessment', '',
        'This proves a static mismatch-shaped path: the host allocates LFSOutput from the host-side size calculator, but H17 write-DMA consumes the surface address and independently derives its DMA extent from geometry without reading the serialized backing-size field.', '',
        'This is stronger than the earlier CodedData candidate, where hardware is explicitly programmed with the backing capacity. It is still **not proof of memory corruption**. The remaining safe proof gap is to symbolically compare the beta3 host allocation-size formula with the firmware DMA-extent formula over the accepted input domain, without producing a concrete triggering dimension pair.'
    ]
    Path(sys.argv[5]).write_text('\n'.join(out) + '\n')
    print('\n'.join(out))

if __name__ == '__main__':
    main()
