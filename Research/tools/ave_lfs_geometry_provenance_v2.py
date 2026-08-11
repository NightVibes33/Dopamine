#!/usr/bin/env python3
"""Corrected LFS geometry provenance wrapper.

Uses the beta4 LFS name xref to map the same LC_FUNCTION_STARTS index back to
beta3, where the function-name string is absent. Static/offline only.
"""
import sys
from pathlib import Path

import ave_dimension_flow_map as dimension_flow
import ave_lfs_geometry_provenance as base


def movz_w(word):
    if word & 0x7F800000 == 0x52800000:
        return word & 31, ((word >> 5) & 0xFFFF) << (((word >> 21) & 3) * 16)
    return None


def find_host_flow(k3_path, k4_path):
    flow = dimension_flow.analyze(k3_path, k4_path)
    b3 = base.KextMachO(k3_path)
    b4 = base.KextMachO(k4_path)

    named = b4.function_referencing('AVE_CalcBufSizeOfLFSOutput')
    if len(named) != 1:
        raise RuntimeError(f'beta4 LFS calculator ambiguous: {named}')
    index = b4.functions.index(named[0])
    if index >= len(b3.functions):
        raise RuntimeError('beta3 LFS function index missing')
    lfs3 = b3.functions[index]

    width = flow['session_width']
    height = flow['session_height']
    matches = []
    for function in b3.functions:
        words = b3.words(function)
        if not words:
            continue
        all_loads = []
        for pc, word in words:
            load = base.ldr_w(word)
            if load and load[2] in (width, height):
                all_loads.append((pc, load))
        if {load[2] for _, load in all_loads} != {width, height}:
            continue
        for i, (pc, word) in enumerate(words):
            if base.bl_target(pc, word) != lfs3:
                continue
            window = words[max(0, i-12):i]
            if not any(movz_w(w) == (0, 2) for _, w in window):
                continue
            matches.append((function, pc, all_loads))

    if len(matches) != 1:
        raise RuntimeError(f'beta3 family-2 LFS caller ambiguous: {matches}')
    return flow, index, lfs3, matches[0]


def main():
    if len(sys.argv) != 6:
        raise SystemExit('usage: ave_lfs_geometry_provenance_v2.py <b3-kext> <b4-kext> <b3-fw> <b4-fw> <output.md>')

    flow, lfs_index, lfs3, host = find_host_flow(sys.argv[1], sys.argv[2])
    fw3 = base.firmware_provenance(sys.argv[3])
    fw4 = base.firmware_provenance(sys.argv[4])

    out = [
        '# AppleAVE2 LFSOutput geometry provenance v2', '',
        'Static/offline validation only. This report intentionally does not derive or print a triggering dimension pair.', '',
        '## Proven host provenance', '',
        f"- selector-4 request width/height: `+0x{flow['request_width']:x}` / `+0x{flow['request_height']:x}`",
        f"- unchanged session width/height: `+0x{flow['session_width']:x}` / `+0x{flow['session_height']:x}`",
        f"- beta3 `AVE_CalcBufSizeOfLFSOutput`: LC_FUNCTION_STARTS index `{lfs_index}`, `0x{lfs3:x}`",
        f"- unique beta3 family-2 LFS caller: `0x{host[0]:x}`, call `0x{host[1]:x}`",
        '- that caller contains the proven session width/height loads and invokes the LFS calculator with family selector 2; its call-site register setup supplies those dimensions as arguments 3/4', '',
        '## Proven H17 firmware provenance', '',
        f"- beta3 `COFController::InitEncodingParameters`: `0x{fw3['init']:x}` loads pInitParams geometry at relative `+0x3c` / `+0x40`",
        f"- beta3 `CLRMEFSController::HwBlockInit`: `0x{fw3['hwinit']:x}` publishes controller `+0x18` into the LRMEFS sequence-init state",
        '- `CLRMEFSController::ConfigWrDMALowResSrcScaled` contains an assertion expression explicitly naming `m_psSequenceInits.uWidthInMbs` and uses controller `+0x18`; this anchors `+0x18` as the horizontal macroblock/grid count',
        '- `ConfigWrDMALowResFSRslts` consumes the paired controller `+0x18/+0x1c` values; the second value controls the vertical repetition/count in the total write-DMA extent',
        '- beta4 reproduces the same provenance structure after address movement', '',
        '## Cross-IPC observation', '',
        '- selector-4 width/height are at relative `+0x3c/+0x40` inside the copied `0x5c0` request substructure (`request +0x338`)',
        '- H17 reads its initialization geometry at relative `+0x3c/+0x40` inside `pInitParams`',
        '- the matching relative offsets are strong structural evidence, but offset equality alone is not sufficient proof that `pInitParams` is the exact host `0x5c0` substructure', '',
        '## Remaining proof gap', '',
        '**Still not proven:** the host command construction must be shown to serialize/session-map that exact `0x5c0` block into H17 `pInitParams` without field remapping.', '',
        'No memory corruption or useful kernel primitive is claimed by this report.'
    ]
    Path(sys.argv[5]).write_text('\n'.join(out) + '\n')
    print('\n'.join(out))


if __name__ == '__main__':
    main()
