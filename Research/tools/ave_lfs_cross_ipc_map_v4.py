#!/usr/bin/env python3
"""LFS cross-IPC proof with per-build session layout discovery.

The vulnerable beta3 path is proven exactly. Beta4 is used as the patched
structural control and may move the session block. Static/offline only.
"""
from pathlib import Path
import sys

import ave_lfs_cross_ipc_map as core
import ave_dimension_flow_map as dimension_flow
import ave_lfs_geometry_provenance as geom


def movz(word):
    if (word & 0x7F800000) == 0x52800000 or (word & 0xFF800000) == 0xD2800000:
        return word & 31, ((word >> 5) & 0xFFFF) << (((word >> 21) & 3) * 16)
    return None


core.movz = movz


def discover_builder(kext, codec):
    funcs = kext.function_referencing(f'AVE_CHM_MakeFwCmd_Start_{codec}')
    if len(funcs) != 1:
        raise RuntimeError(f'{codec}: start builder ambiguous: {funcs}')
    fn = funcs[0]
    words = kext.words(fn)

    dst = [(i,pc,mv[0]) for i,(pc,w) in enumerate(words) if (mv := movz(w)) and mv[1] == 0x2DF0]
    length = [(i,pc,mv[0]) for i,(pc,w) in enumerate(words) if (mv := movz(w)) and mv == (2,0x5C0)]
    if not dst or not length:
        raise RuntimeError(f'{codec}: command +0x2df0 / length 0x5c0 signature missing')

    candidates = []
    for di,dpc,dreg in dst:
        for li,lpc,_ in length:
            window = words[max(0,min(di,li)-18):min(len(words),max(di,li)+12)]
            dst_add = next((pc for pc,w in window if (a := core.add_reg_x(w)) and a[0] == 0 and a[2] == dreg), None)
            if not dst_add:
                continue
            for si,(spc,sw) in enumerate(words):
                mv = movz(sw)
                if not mv or mv[1] in (0,0x2DF0,0x5C0):
                    continue
                sreg, soff = mv
                if abs(si-di) > 28:
                    continue
                src_add = next((pc for pc,w in window if (a := core.add_reg_x(w)) and a[0] == 1 and a[2] == sreg), None)
                if not src_add:
                    continue
                calls = [(pc,core.bl_target(pc,w)) for pc,w in window if core.bl_target(pc,w)]
                if calls:
                    candidates.append((soff, fn, src_add, dst_add, lpc, calls[0][0], calls[0][1]))
    # Prefer the expected copied-structure-sized source offset range, and require one value.
    offsets = sorted({row[0] for row in candidates if 0x1000 <= row[0] <= 0x3000})
    if len(offsets) != 1:
        raise RuntimeError(f'{codec}: source session offset ambiguous: {offsets}; candidates={candidates[:8]}')
    chosen = next(row for row in candidates if row[0] == offsets[0])
    return chosen


def main():
    if len(sys.argv) != 6:
        raise SystemExit('usage: ave_lfs_cross_ipc_map_v4.py <b3-kext> <b4-kext> <b3-fw> <b4-fw> <output.md>')
    k3p,k4p,fw3p,fw4p,outp = sys.argv[1:]
    flow = dimension_flow.analyze(k3p,k4p)
    k3 = geom.KextMachO(k3p)
    k4 = geom.KextMachO(k4p)

    b3 = {codec: discover_builder(k3,codec) for codec in ('AVC','HEVC','AV1')}
    b4 = {codec: discover_builder(k4,codec) for codec in ('AVC','HEVC','AV1')}
    b3_offsets = {row[0] for row in b3.values()}
    b4_offsets = {row[0] for row in b4.values()}
    if b3_offsets != {flow['session_copy_offset']} or flow['session_copy_offset'] != 0x1680:
        raise RuntimeError(f'beta3 start builders do not use proven selector4 session block: {b3_offsets}')
    if len(b4_offsets) != 1:
        raise RuntimeError(f'beta4 start builders disagree on session block: {b4_offsets}')
    beta4_session = next(iter(b4_offsets))

    fw3 = core.inspect_firmware(fw3p)
    fw4 = core.inspect_firmware(fw4p)

    if (flow['request_width'] - flow['request_substructure'], flow['request_height'] - flow['request_substructure']) != (0x3C,0x40):
        raise RuntimeError('beta3 selector4 geometry is no longer relative +0x3c/+0x40')
    if flow['session_width'] != 0x16BC or flow['session_height'] != 0x16C0:
        raise RuntimeError('beta3 session geometry offsets changed')

    cmd_width = 0x2DF0 + 0x3C
    cmd_height = 0x2DF0 + 0x40
    lines = [
        '# AppleAVE2 LFS cross-IPC geometry map v4', '',
        'Static/offline validation only. No triggering dimension values are produced.', '',
        '## Vulnerable beta3 exact flow', '',
        '- selector 4 copies request substructure `+0x338`, length `0x5c0`, into session `+0x1680`',
        '- request width/height `+0x374/+0x378` become session `+0x16bc/+0x16c0` (relative `+0x3c/+0x40`)',
        '- all beta3 AVC/HEVC/AV1 start builders copy session `+0x1680`, length `0x5c0`, into firmware command `+0x2df0`',
        f'- therefore command width/height are `+0x{cmd_width:x}/+0x{cmd_height:x}`',
        f"- H17 `COFController::Init` (`0x{fw3['init']:x}`) stores command `+0x2df0` as command-info `+0x8`",
        f"- H17 vtable dispatch reaches `ProcessInit` (`0x{fw3['process']:x}`) then `InitEncodingParameters` (`0x{fw3['initenc']:x}`)",
        '- `InitEncodingParameters` loads that `+0x8` pointer as `pInitParams` and reads geometry at `pInitParams +0x3c/+0x40`', '',
        '## Patched beta4 control', '',
        f'- beta4 moved the corresponding host session block to `+0x{beta4_session:x}` but still copies length `0x5c0` to command `+0x2df0` in all three codec start builders',
        '- beta4 H17 preserves the same command `+0x2df0` -> `pInitParams +0x3c/+0x40` parser structure', '',
        '## Conclusion', '',
        '**The beta3 cross-IPC geometry mapping is proven:** request `+0x374/+0x378` -> session `+0x16bc/+0x16c0` -> firmware command `+0x2e2c/+0x2e30` -> H17 `pInitParams +0x3c/+0x40`.', '',
        'This closes the field-equivalence gap for the LFSOutput candidate. It still does not prove memory corruption or a useful kernel primitive, and it intentionally does not derive a triggering dimension pair.'
    ]
    Path(outp).write_text('\n'.join(lines)+'\n')
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
