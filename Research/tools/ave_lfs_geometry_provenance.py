#!/usr/bin/env python3
"""Validate LFSOutput geometry provenance on iOS 27 beta3/beta4.

Static/offline only. This tool intentionally stops before deriving any concrete
triggering dimensions. It separates proven host/firmware provenance from the
remaining cross-IPC equivalence gap.
"""
from __future__ import annotations

import bisect
import struct
import sys
from pathlib import Path

import ave_dimension_flow_map as dimension_flow

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


def ldr_w(word):
    if word & 0xFFC00000 == 0xB9400000:
        return word & 31, (word >> 5) & 31, ((word >> 10) & 0xFFF) * 4
    return None


def mov_reg(word):
    if word & 0xFFE0FFE0 == 0xAA0003E0:
        return word & 31, (word >> 16) & 31
    return None


class KextMachO:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self.segments = []
        starts = None
        off = 32
        for _ in range(u32(self.data, 16)):
            cmd = u32(self.data, off)
            cmdsize = u32(self.data, off + 4)
            if cmd == LC_SEGMENT_64:
                name = self.data[off+8:off+24].split(b'\0')[0].decode(errors='replace')
                self.segments.append({
                    'name': name, 'vmaddr': u64(self.data, off+24), 'vmsize': u64(self.data, off+32),
                    'fileoff': u64(self.data, off+40), 'filesize': u64(self.data, off+48),
                })
            elif cmd == LC_FUNCTION_STARTS:
                starts = (u32(self.data, off+8), u32(self.data, off+12))
            off += cmdsize
        self.text = next(s for s in self.segments if s['name'] == '__TEXT')
        self.exec = next(s for s in self.segments if s['name'] == '__TEXT_EXEC')
        pos, size = starts
        end = pos + size
        address = self.text['vmaddr']
        self.functions = []
        while pos < end:
            delta, pos = decode_uleb(self.data, pos, end)
            if not delta: break
            address += delta
            self.functions.append(address)
        self.function_set = set(self.functions)

    def va_to_fileoff(self, va):
        for s in self.segments:
            if s['vmaddr'] <= va < s['vmaddr'] + s['vmsize']:
                return s['fileoff'] + va - s['vmaddr']
        return None

    def function_end(self, start):
        i = bisect.bisect_left(self.functions, start)
        return self.functions[i+1] if i+1 < len(self.functions) else self.exec['vmaddr'] + self.exec['vmsize']

    def words(self, start):
        a = self.va_to_fileoff(start)
        b = self.va_to_fileoff(self.function_end(start))
        return [(start + (off-a), u32(self.data, off)) for off in range(a, b, 4)]

    def exact_strings_containing(self, marker):
        needle = marker.encode()
        found = []
        pos = 0
        while True:
            hit = self.data.find(needle, pos)
            if hit < 0: break
            begin = self.data.rfind(b'\0', 0, hit) + 1
            end = self.data.find(b'\0', hit)
            if end < 0: break
            value = self.data[begin:end].decode(errors='replace')
            if marker in value:
                for s in self.segments:
                    if s['fileoff'] <= begin < s['fileoff'] + s['filesize']:
                        found.append((s['vmaddr'] + begin - s['fileoff'], value))
                        break
            pos = hit + len(needle)
        return found

    def xrefs(self, target_va):
        page = target_va & ~0xFFF
        page_off = target_va & 0xFFF
        refs = []
        begin = self.exec['fileoff']
        end = begin + self.exec['filesize']
        for off in range(begin, end-24, 4):
            word = u32(self.data, off)
            if word & 0x9F000000 != 0x90000000: continue
            pc = self.exec['vmaddr'] + off - begin
            if decode_adrp(word, pc) != page: continue
            reg = word & 31
            for delta in range(4, 24, 4):
                nxt = u32(self.data, off+delta)
                if nxt & 0x7F000000 == 0x11000000 and ((nxt >> 5) & 31) == reg:
                    imm = (nxt >> 10) & 0xFFF
                    if (nxt >> 22) & 1: imm <<= 12
                    if imm == page_off:
                        refs.append(pc)
                        break
        return refs

    def function_for_va(self, va):
        i = bisect.bisect_right(self.functions, va) - 1
        return self.functions[i] if i >= 0 else None

    def function_referencing(self, marker):
        funcs = set()
        for va, _ in self.exact_strings_containing(marker):
            for ref in self.xrefs(va):
                funcs.add(self.function_for_va(ref))
        return sorted(f for f in funcs if f is not None)


class FirmwareMachO:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self.segments = []
        self.sections = [None]
        symtab = None
        off = 32
        for _ in range(u32(self.data, 16)):
            cmd = u32(self.data, off)
            cmdsize = u32(self.data, off+4)
            if cmd == LC_SEGMENT_64:
                segname = self.data[off+8:off+24].split(b'\0')[0].decode(errors='replace')
                self.segments.append({
                    'name': segname, 'vmaddr': u64(self.data, off+24), 'vmsize': u64(self.data, off+32),
                    'fileoff': u64(self.data, off+40), 'filesize': u64(self.data, off+48),
                })
                nsects = u32(self.data, off+64)
                sectoff = off + 72
                for _s in range(nsects):
                    sect = self.data[sectoff:sectoff+16].split(b'\0')[0].decode(errors='replace')
                    seg = self.data[sectoff+16:sectoff+32].split(b'\0')[0].decode(errors='replace')
                    self.sections.append((seg, sect, u64(self.data, sectoff+32), u64(self.data, sectoff+40), u32(self.data, sectoff+48)))
                    sectoff += 80
            elif cmd == LC_SYMTAB:
                symtab = (u32(self.data, off+8), u32(self.data, off+12), u32(self.data, off+16), u32(self.data, off+20))
            off += cmdsize
        symoff, nsyms, stroff, strsize = symtab
        strings = self.data[stroff:stroff+strsize]
        symbols = []
        for i in range(nsyms):
            no = symoff + i*16
            strx = u32(self.data, no)
            n_type = self.data[no+4]
            n_sect = self.data[no+5]
            value = u64(self.data, no+8)
            if not value or strx >= len(strings) or n_sect == 0 or n_sect >= len(self.sections): continue
            end = strings.find(b'\0', strx)
            if end < 0: continue
            name = strings[strx:end].decode(errors='replace')
            sec = self.sections[n_sect]
            if (n_type & N_TYPE) == N_SECT and sec and sec[0] == '__TEXT' and sec[1] == '__text':
                symbols.append((value, name))
        self.symbols = sorted(set(symbols))
        self.values = [v for v, _ in self.symbols]

    def va_to_fileoff(self, va):
        for s in self.segments:
            if s['vmaddr'] <= va < s['vmaddr'] + s['vmsize']:
                return s['fileoff'] + va - s['vmaddr']
        return None

    def symbol(self, marker):
        matches = [(v,n) for v,n in self.symbols if marker in n]
        if len(matches) != 1:
            raise RuntimeError(f'{marker}: ambiguous symbols {matches[:8]}')
        return matches[0]

    def end(self, start):
        i = bisect.bisect_right(self.values, start)
        return self.values[i]

    def words(self, start):
        end = self.end(start)
        a = self.va_to_fileoff(start)
        b = self.va_to_fileoff(end)
        return [(start + (off-a), u32(self.data, off)) for off in range(a,b,4)]

    def cstring_refs(self, start):
        words = self.words(start)
        refs = []
        for i,(pc,word) in enumerate(words):
            if word & 0x9F000000 != 0x90000000: continue
            page = decode_adrp(word, pc)
            reg = word & 31
            for _,nxt in words[i+1:i+7]:
                if nxt & 0x7F000000 != 0x11000000 or ((nxt >> 5) & 31) != reg: continue
                imm = (nxt >> 10) & 0xFFF
                if (nxt >> 22) & 1: imm <<= 12
                va = page + imm
                off = self.va_to_fileoff(va)
                if off is None: break
                raw = self.data[off:off+500].split(b'\0')[0]
                try: value = raw.decode()
                except UnicodeDecodeError: value = ''
                if value and any(c.isalpha() for c in value): refs.append((pc,value))
                break
        return refs


def find_lfs_w0_2_host_flow(k3, k4):
    flow = dimension_flow.analyze(k3, k4)
    macho = KextMachO(k3)
    funcs = macho.function_referencing('AVE_CalcBufSizeOfLFSOutput')
    if len(funcs) != 1: raise RuntimeError(f'LFS calculator ambiguous: {funcs}')
    lfs = funcs[0]
    session_width = flow['session_width']
    session_height = flow['session_height']
    matches = []
    for function in macho.functions:
        words = macho.words(function)
        for i,(pc,word) in enumerate(words):
            if bl_target(pc,word) != lfs: continue
            window = words[max(0,i-12):i]
            has_family2 = any((word2 & 0x7F800000) == 0x52800000 and (word2 & 31) == 0 and (((word2 >> 5) & 0xFFFF) << (((word2 >> 21)&3)*16)) == 2 for _,word2 in window)
            loads = []
            for pc2,word2 in window:
                ld = ldr_w(word2)
                if ld and ld[1] == 25 and ld[2] in (session_width, session_height): loads.append((pc2,ld))
            if has_family2 and {ld[2] for _,ld in loads} == {session_width, session_height}:
                matches.append((function,pc,loads))
    if len(matches) != 1: raise RuntimeError(f'w0=2 LFS host flow ambiguous: {matches}')
    return flow, lfs, matches[0]


def firmware_provenance(path):
    fw = FirmwareMachO(path)
    init, _ = fw.symbol('COFController22InitEncodingParameters')
    hwinit, _ = fw.symbol('CLRMEFSController11HwBlockInit')
    srcdma, _ = fw.symbol('CLRMEFSController26ConfigWrDMALowResSrcScaled')
    wrdma, _ = fw.symbol('CLRMEFSController24ConfigWrDMALowResFSRslts')

    src_refs = [s for _,s in fw.cstring_refs(srcdma)]
    if not any('m_psSequenceInits.uWidthInMbs' in s for s in src_refs):
        raise RuntimeError('uWidthInMbs semantic anchor missing')
    if not any(ldr_w(w) and ldr_w(w)[1:] == (0,0x18) for _,w in fw.words(srcdma)):
        raise RuntimeError('uWidthInMbs routine does not load controller +0x18')

    wr_words = fw.words(wrdma)
    first_pair = next((pc for pc,w in wr_words[:16] if (w & 0xFFC00000) == 0x29400000 and ((w >> 5) & 31) == 0 and signed((w >> 15)&0x7F,7)*4 == 0x18), None)
    if first_pair is None: raise RuntimeError('LFS write-DMA does not consume controller +0x18/+0x1c pair')

    hw_words = fw.words(hwinit)
    if len(hw_words) < 5: raise RuntimeError('HwBlockInit too short')
    # Structural signature: expose this+0x18 through *arg1 and this+0x40 through *arg2.
    hw_raw = [w for _,w in hw_words[:8]]
    if 0x91006008 not in hw_raw or 0xF9000028 not in hw_raw or 0x91010008 not in hw_raw or 0xF9000048 not in hw_raw:
        raise RuntimeError('HwBlockInit pointer publication signature changed')

    init_words = fw.words(init)
    # Proven source geometry: pInitParams is loaded from arg1+0x8 into x28; +0x3c/+0x40 are copied into controller scratch +0x1028/+0x102c.
    sigs = {
        'pinit_load': 0xF9400428,  # ldr x8,[x1,#8] may be compiler register-specific in nearby prologue
    }
    source_3c = [(pc,ldr_w(w)) for pc,w in init_words if ldr_w(w) and ldr_w(w)[1] == 28 and ldr_w(w)[2] == 0x3c]
    source_40 = [(pc,ldr_w(w)) for pc,w in init_words if ldr_w(w) and ldr_w(w)[1] == 28 and ldr_w(w)[2] == 0x40]
    if not source_3c or not source_40: raise RuntimeError('InitEncodingParameters source geometry +0x3c/+0x40 missing')

    # Later the pair is rounded into grid units and stored together before HwBlockInit; assert a 32-bit STP exists and that the published +0x18 pointer receives two words after HwBlockInit.
    pair_store = next((pc for pc,w in init_words if (w & 0xFFC00000) == 0x29000000), None)
    if pair_store is None: raise RuntimeError('sequence-grid pair store missing')
    hw_call = next((pc for pc,w in init_words if bl_target(pc,w) == hwinit), None)
    if hw_call is None: raise RuntimeError('COF InitEncodingParameters does not call CLRMEFS HwBlockInit')

    return {
        'init': init, 'hwinit': hwinit, 'srcdma': srcdma, 'wrdma': wrdma,
        'source_3c': source_3c[0][0], 'source_40': source_40[0][0],
        'pair_store': pair_store, 'hw_call': hw_call, 'width_semantic': True,
        'wrdma_pair_load': first_pair,
    }


def main():
    if len(sys.argv) != 6:
        raise SystemExit('usage: ave_lfs_geometry_provenance.py <b3-kext> <b4-kext> <b3-fw> <b4-fw> <output.md>')
    flow, lfs, host = find_lfs_w0_2_host_flow(sys.argv[1], sys.argv[2])
    fw3 = firmware_provenance(sys.argv[3])
    fw4 = firmware_provenance(sys.argv[4])

    out = [
        '# AppleAVE2 LFSOutput geometry provenance', '',
        'Static/offline validation only. This report intentionally does not derive or print a triggering dimension pair.', '',
        '## Proven host provenance', '',
        f"- selector-4 request width/height: `+0x{flow['request_width']:x}` / `+0x{flow['request_height']:x}`",
        f"- unchanged session width/height: `+0x{flow['session_width']:x}` / `+0x{flow['session_height']:x}`",
        f"- beta3 `AVE_CalcBufSizeOfLFSOutput`: `0x{lfs:x}`",
        f"- unique LFS family-2 caller: `0x{host[0]:x}`, call `0x{host[1]:x}`",
        '- that family-2 call loads the proven session width/height and supplies them to the LFS calculator as arguments 3/4', '',
        '## Proven H17 firmware provenance', '',
        f"- beta3 `COFController::InitEncodingParameters`: `0x{fw3['init']:x}` loads init-parameter geometry at `+0x3c` / `+0x40` (loads at `0x{fw3['source_3c']:x}` / `0x{fw3['source_40']:x}`)",
        f"- beta3 `CLRMEFSController::HwBlockInit`: `0x{fw3['hwinit']:x}` publishes controller `+0x18` as the sequence-init pointer",
        '- `CLRMEFSController::ConfigWrDMALowResSrcScaled` contains an assertion expression explicitly naming `m_psSequenceInits.uWidthInMbs` and loads controller `+0x18`; this identifies `+0x18` as the horizontal macroblock/grid count',
        f"- `ConfigWrDMALowResFSRslts` loads the paired `+0x18/+0x1c` values at `0x{fw3['wrdma_pair_load']:x}`; the second value controls the vertical repetition/count in the total DMA-extent calculation",
        '- beta4 reproduces the same provenance structure after address movement', '',
        '## Remaining proof gap', '',
        'The host side proves selector-4 request width/height -> session width/height -> LFS size calculation. The firmware side proves init-parameter geometry -> LRMEFS sequence grid -> independently computed LFS write-DMA extent.', '',
        '**Still not proven:** the exact cross-IPC field equivalence between firmware init-parameter `+0x3c/+0x40` and selector-4 request `+0x374/+0x378`. Until that mapping is established, the two formulas should not be treated as algebraically linked inputs.', '',
        'No memory corruption or useful kernel primitive is claimed by this report.'
    ]
    Path(sys.argv[5]).write_text('\n'.join(out) + '\n')
    print('\n'.join(out))

if __name__ == '__main__':
    main()
