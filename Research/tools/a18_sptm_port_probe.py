#!/usr/bin/env python3
"""Offline A18 SPTM layout probe.

Maps iOS 27 A18 SPTM routines that correspond to older A12/A13
boot-chain patchfinder targets. This tool does not patch firmware.
"""

import argparse
import struct
from pathlib import Path

PACIBSP = 0xD503237F
BTI_C = 0xD503245F
FUNC_STARTS = {PACIBSP, BTI_C}


def rd32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def rd64(data, off):
    return struct.unpack_from('<Q', data, off)[0]


def decode_adrp_imm(word):
    immhi = (word >> 5) & 0x7FFFF
    immlo = (word >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return imm


class MachOProbe:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.segments = []
        self._parse_segments()
        self.text_exec = next(seg for seg in self.segments if seg['name'] == '__TEXT_EXEC')

    def _parse_segments(self):
        ncmds = rd32(self.data, 16)
        off = 32
        for _ in range(ncmds):
            cmd = rd32(self.data, off)
            cmdsize = rd32(self.data, off + 4)
            if cmd == 0x19:
                name = self.data[off + 8:off + 24].split(b'\0')[0].decode(errors='replace')
                self.segments.append({
                    'name': name,
                    'vmaddr': rd64(self.data, off + 24),
                    'vmsize': rd64(self.data, off + 32),
                    'fileoff': rd64(self.data, off + 40),
                    'filesize': rd64(self.data, off + 48),
                })
            off += cmdsize

    def foff_to_va(self, foff):
        for seg in self.segments:
            start = int(seg['fileoff'])
            end = start + int(seg['filesize'])
            if start <= foff < end:
                return int(seg['vmaddr']) + (foff - start)
        return None

    def find_string(self, value):
        off = self.data.find(value.encode())
        return off if off >= 0 else None

    def refs_to_string(self, string_off):
        string_va = self.foff_to_va(string_off)
        if string_va is None:
            return []
        page = string_va & ~0xFFF
        page_off = string_va & 0xFFF
        start = int(self.text_exec['fileoff'])
        end = start + int(self.text_exec['filesize'])
        refs = []

        for foff in range(start, end - 24, 4):
            word = rd32(self.data, foff)
            if (word & 0x9F000000) != 0x90000000:
                continue
            pc = self.foff_to_va(foff)
            target_page = ((pc & ~0xFFF) + (decode_adrp_imm(word) << 12)) & 0xFFFFFFFFFFFFFFFF
            if target_page != page:
                continue
            reg = word & 0x1F
            for delta in range(4, 24, 4):
                nxt = rd32(self.data, foff + delta)
                if (nxt & 0x7F000000) != 0x11000000:
                    continue
                if ((nxt >> 5) & 0x1F) != reg:
                    continue
                imm = (nxt >> 10) & 0xFFF
                if (nxt >> 22) & 1:
                    imm <<= 12
                if imm == page_off:
                    refs.append(foff)
                    break
        return refs

    def find_func_start(self, off):
        lower = max(int(self.text_exec['fileoff']), off - 0x4000)
        for foff in range(off & ~3, lower, -4):
            if rd32(self.data, foff) in FUNC_STARTS:
                return foff
        return None

    def find_next_func(self, off):
        end = int(self.text_exec['fileoff'] + self.text_exec['filesize'])
        for foff in range(off + 4, end, 4):
            if rd32(self.data, foff) in FUNC_STARTS:
                return foff
        return end

    def map_named_function(self, name):
        string_off = self.find_string(name)
        if string_off is None:
            return None
        refs = self.refs_to_string(string_off)
        if not refs:
            return None
        func = self.find_func_start(refs[0])
        if func is None:
            return None
        end = self.find_next_func(func)
        words = [rd32(self.data, off) for off in range(func, end, 4)]
        msr_count = sum(1 for word in words if (word & 0xFFF00000) == 0xD5100000)
        bl_count = sum(1 for word in words if (word & 0xFC000000) == 0x94000000)
        return {
            'fileoff': func,
            'va': self.foff_to_va(func),
            'size': end - func,
            'refs': refs,
            'msr_count': msr_count,
            'bl_count': bl_count,
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('sptm', type=Path)
    args = ap.parse_args()

    probe = MachOProbe(args.sptm)
    names = [
        'ctrr_lock_boot',
        'cpu_lock_system_registers',
        'ctrr_lock_sptm',
        'assert_ctrr_group_region_unlocked',
        'sptm_determine_kernel_ctrr',
        'ctrr_amcc_find_lock_group_data',
        'ctrr_stash_group_regions',
        'ctrr_map_lock_group',
    ]

    print(f'# {args.sptm.name}')
    for name in names:
        result = probe.map_named_function(name)
        if result is None:
            print(f'{name}: NOT_FOUND')
            continue
        print(
            f"{name}: fileoff=0x{result['fileoff']:x} va=0x{result['va']:x} "
            f"size=0x{result['size']:x} msr={result['msr_count']} calls={result['bl_count']}"
        )


if __name__ == '__main__':
    main()
