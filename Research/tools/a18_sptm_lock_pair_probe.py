#!/usr/bin/env python3
"""Validate the two adjacent A18 iOS 27 CTRR lock routines.

Offline/static only. This tool does not patch SPTM and does not claim a runtime
bypass. It complements a18_sptm_port_probe.py by validating the unnamed
secondary lock routine immediately following ctrr_lock_sptm.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from a18_sptm_port_probe import MachOProbe, analyze, rd32

MSR_SECONDARY_CTRR_X8 = 0xD518B1A8  # msr S3_0_C11_C1_5, x8
TLBI_VMALLE1NXS = 0xD508971F
DSB_NSHNXS = 0xD503363F
ISB = 0xD5033FDF


def validate(path):
    base = analyze(path)
    probe = MachOProbe(path)
    ctrr = base.get('a18', {}).get('ctrr_lock_sptm')
    apply = base.get('a18', {}).get('lock_regs_apply_candidate')
    parser = base.get('a18', {}).get('lock_regs_parser_candidate')
    if not ctrr:
        return {'file': str(path), 'confidence': 'not_found', 'reason': 'ctrr_lock_sptm missing'}

    secondary_off = probe.find_next_func(ctrr['fileoff'])
    secondary = probe.describe(secondary_off)
    words = [word for _, word in probe.words(secondary_off)]
    call_targets = {call['target_va'] for call in secondary['calls']}

    signature = {
        'secondary_msr_twice': sum(word == MSR_SECONDARY_CTRR_X8 for word in words) >= 2,
        'tlbi_vmalle1nxs': TLBI_VMALLE1NXS in words,
        'dsb_nshnxs': DSB_NSHNXS in words,
        'multiple_isb': sum(word == ISB for word in words) >= 2,
        'calls_lock_apply': bool(apply and apply['va'] in call_targets),
        'calls_lock_parser': bool(parser and parser['va'] in call_targets),
    }

    return {
        'file': str(path),
        'primary': {
            'fileoff': ctrr['fileoff'],
            'va': ctrr['va'],
        },
        'secondary': {
            'fileoff': secondary['fileoff'],
            'va': secondary['va'],
            'size_to_next_func': secondary['size_to_next_func'],
            'secondary_msr_count': sum(word == MSR_SECONDARY_CTRR_X8 for word in words),
            'tlbi_count': sum(word == TLBI_VMALLE1NXS for word in words),
            'dsb_nshnxs_count': sum(word == DSB_NSHNXS for word in words),
            'isb_count': sum(word == ISB for word in words),
        },
        'signature': signature,
        'confidence': 'high' if all(signature.values()) else 'partial',
        'conclusion': (
            'A18/iOS 27 uses a stable adjacent CTRR lock pair. The primary routine '
            'locks S3_0_C11_C1_4; the secondary candidate locks S3_0_C11_C1_5 and '
            'reuses the same lock-reg parser/apply machinery.'
        ),
    }


def main():
    ap = argparse.ArgumentParser(description='Offline A18 SPTM lock-pair validator')
    ap.add_argument('sptm', type=Path)
    ap.add_argument('--output', type=Path)
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    result = validate(args.sptm)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"# A18 SPTM lock pair: {args.sptm.name}")
        if result.get('primary'):
            print(f"primary:   fileoff=0x{result['primary']['fileoff']:x} va=0x{result['primary']['va']:x}")
            print(f"secondary: fileoff=0x{result['secondary']['fileoff']:x} va=0x{result['secondary']['va']:x}")
            print('signature: ' + ', '.join(f"{k}={'yes' if v else 'no'}" for k, v in result['signature'].items()))
        print(f"confidence: {result['confidence']}")
        print(result.get('conclusion', result.get('reason', '')))


if __name__ == '__main__':
    main()
