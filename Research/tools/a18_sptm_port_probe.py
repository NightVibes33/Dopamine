#!/usr/bin/env python3
"""Offline A18 SPTM structural analyzer for iOS 27.

This tool does NOT modify firmware. It identifies A18 replacements for older
A12/A13 SPTM patchfinder targets using strings, xrefs, call relationships, and
instruction signatures. Results are intended for static validation only.
"""

import argparse
import json
import struct
from pathlib import Path

PACIBSP = 0xD503237F
BTI_C = 0xD503245F
FUNC_STARTS = {PACIBSP, BTI_C}

# A18/iOS 27 lock-path instructions that are stable across beta 3/4/5.
MRS_CTRR_STATE_0_X8 = 0xD538B188  # mrs x8, S3_0_C11_C1_4
MRS_CTRR_STATE_1_X8 = 0xD538B1A8  # mrs x8, S3_0_C11_C1_5
MSR_CTRR_STATE_0_X8 = 0xD518B188  # msr S3_0_C11_C1_4, x8
TLBI_VMALLE1NXS = 0xD508971F
DSB_NSHNXS = 0xD503363F
DSB_SY = 0xD5033F9F
ISB = 0xD5033FDF
MRS_SOC_BASE_X8 = 0xD53EF808
MRS_SOC_BASE_X16 = 0xD53EFB30
MRS_SOC_BASE_X17 = 0xD53EFB31


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


def decode_bl_target(pc, word):
    imm26 = word & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    return (pc + (imm26 << 2)) & 0xFFFFFFFFFFFFFFFF


class MachOProbe:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.segments = []
        self._parse_segments()
        self.text_exec = next(seg for seg in self.segments if seg['name'] == '__TEXT_EXEC')
        self.adrp_index = self._build_adrp_index()

    def _parse_segments(self):
        if len(self.data) < 32:
            raise ValueError('file is too small to be Mach-O')
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
            if cmdsize < 8:
                raise ValueError('invalid Mach-O load command size')
            off += cmdsize

    def text_range(self):
        start = int(self.text_exec['fileoff'])
        return start, start + int(self.text_exec['filesize'])

    def foff_to_va(self, foff):
        for seg in self.segments:
            start = int(seg['fileoff'])
            end = start + int(seg['filesize'])
            if start <= foff < end:
                return int(seg['vmaddr']) + (foff - start)
        return None

    def _build_adrp_index(self):
        index = {}
        start, end = self.text_range()
        for foff in range(start, end - 4, 4):
            word = rd32(self.data, foff)
            if (word & 0x9F000000) != 0x90000000:
                continue
            pc = self.foff_to_va(foff)
            page = ((pc & ~0xFFF) + (decode_adrp_imm(word) << 12)) & 0xFFFFFFFFFFFFFFFF
            index.setdefault(page, []).append(foff)
        return index

    def find_string(self, value):
        off = self.data.find(value.encode())
        return off if off >= 0 else None

    def refs_to_string(self, string_off):
        string_va = self.foff_to_va(string_off)
        if string_va is None:
            return []
        page = string_va & ~0xFFF
        page_off = string_va & 0xFFF
        refs = []
        for foff in self.adrp_index.get(page, []):
            adrp = rd32(self.data, foff)
            reg = adrp & 0x1F
            for delta in range(4, 24, 4):
                nxt_off = foff + delta
                if nxt_off + 4 > len(self.data):
                    break
                nxt = rd32(self.data, nxt_off)
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
        return sorted(set(refs))

    def find_func_start(self, off):
        lower = max(int(self.text_exec['fileoff']), off - 0x4000)
        for foff in range(off & ~3, lower - 1, -4):
            if rd32(self.data, foff) in FUNC_STARTS:
                return foff
        return None

    def find_next_func(self, off):
        _, end = self.text_range()
        for foff in range(off + 4, end, 4):
            if rd32(self.data, foff) in FUNC_STARTS:
                return foff
        return end

    def funcs_referencing_string(self, name):
        string_off = self.find_string(name)
        if string_off is None:
            return []
        funcs = []
        for ref in self.refs_to_string(string_off):
            start = self.find_func_start(ref)
            if start is not None:
                funcs.append(start)
        return sorted(set(funcs))

    def words(self, start, end=None):
        if end is None:
            end = self.find_next_func(start)
        return [(off, rd32(self.data, off)) for off in range(start, min(end, len(self.data)), 4)]

    def bl_targets(self, start, end=None):
        out = []
        for off, word in self.words(start, end):
            if (word & 0xFC000000) == 0x94000000:
                out.append((off, decode_bl_target(self.foff_to_va(off), word)))
        return out

    def describe(self, start):
        end = self.find_next_func(start)
        words = self.words(start, end)
        calls = self.bl_targets(start, end)
        return {
            'fileoff': start,
            'va': self.foff_to_va(start),
            'size_to_next_func': end - start,
            'call_count': len(calls),
            'calls': [{'fileoff': off, 'target_va': target} for off, target in calls],
            'dsb_sy_count': sum(word == DSB_SY for _, word in words),
            'isb_count': sum(word == ISB for _, word in words),
            'tlbi_vmalle1nxs_count': sum(word == TLBI_VMALLE1NXS for _, word in words),
            'ctrr_state_mrs_count': sum(word in (MRS_CTRR_STATE_0_X8, MRS_CTRR_STATE_1_X8) for _, word in words),
            'ctrr_state_msr_count': sum(word == MSR_CTRR_STATE_0_X8 for _, word in words),
            'soc_reg_mrs_count': sum(word in (MRS_SOC_BASE_X8, MRS_SOC_BASE_X16, MRS_SOC_BASE_X17) for _, word in words),
        }


def analyze(path):
    probe = MachOProbe(path)
    result = {
        'file': str(path),
        'size': len(probe.data),
        'legacy': {},
        'a18': {},
        'confidence': {},
    }

    for name in ('ctrr_lock_boot', 'cpu_lock_system_registers'):
        funcs = probe.funcs_referencing_string(name)
        result['legacy'][name] = [probe.describe(func) for func in funcs]

    ctrr_funcs = probe.funcs_referencing_string('ctrr_lock_sptm')
    determine_funcs = probe.funcs_referencing_string('sptm_determine_kernel_ctrr')
    lock_ref_funcs = probe.funcs_referencing_string('/chosen/lock-regs')
    gapf_funcs = probe.funcs_referencing_string('sptm-gapf-lock-reg')

    if not ctrr_funcs:
        result['confidence']['ctrr_lock_sptm'] = 'not_found'
        return result

    ctrr = ctrr_funcs[0]
    ctrr_desc = probe.describe(ctrr)
    ctrr_calls = {call['target_va'] for call in ctrr_desc['calls']}

    lock_funcs = []
    for func in lock_ref_funcs:
        desc = probe.describe(func)
        desc['called_directly_by_ctrr_lock_sptm'] = desc['va'] in ctrr_calls
        lock_funcs.append(desc)

    signature = {
        'reads_both_ctrr_state_regs': ctrr_desc['ctrr_state_mrs_count'] >= 2,
        'writes_ctrr_state_reg_twice': ctrr_desc['ctrr_state_msr_count'] >= 2,
        'has_vmalle1nxs_tlbi': ctrr_desc['tlbi_vmalle1nxs_count'] >= 1,
        'has_isb': ctrr_desc['isb_count'] >= 2,
        'references_lock_regs_path': any(item['called_directly_by_ctrr_lock_sptm'] for item in lock_funcs),
    }

    direct = [item for item in lock_funcs if item['called_directly_by_ctrr_lock_sptm']]
    apply_candidate = None
    if direct:
        apply_candidate = max(
            direct,
            key=lambda item: (
                item['dsb_sy_count'] + item['isb_count'] + item['soc_reg_mrs_count'],
                item['size_to_next_func'],
            ),
        )
    parser_candidate = None
    remaining = [item for item in direct if apply_candidate is None or item['fileoff'] != apply_candidate['fileoff']]
    if remaining:
        parser_candidate = max(remaining, key=lambda item: item['size_to_next_func'])

    result['a18']['ctrr_lock_sptm'] = ctrr_desc
    result['a18']['ctrr_lock_sptm_signature'] = signature
    result['a18']['lock_regs_functions'] = lock_funcs
    result['a18']['lock_regs_parser_candidate'] = parser_candidate
    result['a18']['lock_regs_apply_candidate'] = apply_candidate
    result['a18']['sptm_determine_kernel_ctrr'] = [probe.describe(func) for func in determine_funcs]
    result['a18']['gapf_lock_reg_functions'] = [probe.describe(func) for func in gapf_funcs]

    result['confidence']['ctrr_lock_sptm'] = 'high' if all(signature.values()) else 'partial'
    result['confidence']['lock_regs_apply'] = (
        'high'
        if apply_candidate and apply_candidate['dsb_sy_count'] >= 2 and apply_candidate['soc_reg_mrs_count'] >= 1
        else ('partial' if apply_candidate else 'not_found')
    )
    result['confidence']['sptm_determine_kernel_ctrr'] = 'high' if determine_funcs else 'not_found'
    result['conclusion'] = (
        'A18 reorganizes the legacy lock path around ctrr_lock_sptm and /chosen/lock-regs. '
        'This analyzer identifies structural candidates only and does not patch SPTM or claim a runtime bypass.'
    )
    return result


def hexaddr(value):
    return 'n/a' if value is None else f'0x{value:x}'


def print_human(result):
    print(f"# A18 SPTM structural analysis: {Path(result['file']).name}")
    print(f"legacy ctrr_lock_boot: {'FOUND' if result['legacy']['ctrr_lock_boot'] else 'NOT_FOUND'}")
    print(f"legacy cpu_lock_system_registers: {'FOUND' if result['legacy']['cpu_lock_system_registers'] else 'NOT_FOUND'}")
    ctrr = result.get('a18', {}).get('ctrr_lock_sptm')
    if not ctrr:
        print('A18 ctrr_lock_sptm: NOT_FOUND')
        return
    print(
        f"ctrr_lock_sptm: fileoff={hexaddr(ctrr['fileoff'])} va={hexaddr(ctrr['va'])} "
        f"size_to_next=0x{ctrr['size_to_next_func']:x}"
    )
    signature = result['a18']['ctrr_lock_sptm_signature']
    print('ctrr_lock_sptm signature: ' + ', '.join(f"{key}={'yes' if value else 'no'}" for key, value in signature.items()))
    parser = result['a18'].get('lock_regs_parser_candidate')
    apply = result['a18'].get('lock_regs_apply_candidate')
    if parser:
        print(
            f"lock-reg parser candidate: fileoff={hexaddr(parser['fileoff'])} va={hexaddr(parser['va'])} "
            f"barriers={parser['dsb_sy_count'] + parser['isb_count']} soc-mrs={parser['soc_reg_mrs_count']}"
        )
    if apply:
        print(
            f"lock-reg apply candidate: fileoff={hexaddr(apply['fileoff'])} va={hexaddr(apply['va'])} "
            f"barriers={apply['dsb_sy_count'] + apply['isb_count']} soc-mrs={apply['soc_reg_mrs_count']}"
        )
    determine = result['a18'].get('sptm_determine_kernel_ctrr') or []
    if determine:
        item = determine[0]
        print(f"sptm_determine_kernel_ctrr: fileoff={hexaddr(item['fileoff'])} va={hexaddr(item['va'])}")
    print('confidence: ' + ', '.join(f'{key}={value}' for key, value in result['confidence'].items()))
    print(result['conclusion'])


def main():
    ap = argparse.ArgumentParser(description='Offline A18 iOS 27 SPTM structural analyzer')
    ap.add_argument('sptm', type=Path)
    ap.add_argument('--json', action='store_true', help='emit machine-readable JSON')
    ap.add_argument('--output', type=Path, help='write JSON result to a file')
    args = ap.parse_args()

    result = analyze(args.sptm)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_human(result)


if __name__ == '__main__':
    main()
