#!/usr/bin/env python3
"""Robust entry point for the LFS cross-IPC validator.

Replaces the v1 host start-builder matcher with an explicit MOVZ/effective-
address matcher. Static/offline only; no triggering values are generated.
"""
import ave_lfs_cross_ipc_map as base


def movz(word):
    if (word & 0x7F800000) == 0x52800000 or (word & 0xFF800000) == 0xD2800000:
        return word & 31, ((word >> 5) & 0xFFFF) << (((word >> 21) & 3) * 16)
    return None


def inspect_host_builder(kext, flow, codec):
    funcs = kext.function_referencing(f'AVE_CHM_MakeFwCmd_Start_{codec}')
    if len(funcs) != 1:
        raise RuntimeError(f'{codec} start builder ambiguous: {funcs}')
    function = funcs[0]
    words = kext.words(function)

    positions = {}
    for i, (pc, word) in enumerate(words):
        mv = movz(word)
        if mv and mv[1] in (0x1680, 0x2DF0, 0x5C0):
            positions.setdefault(mv[1], []).append((i, pc, mv[0]))
    for value in (0x1680, 0x2DF0, 0x5C0):
        if value not in positions:
            raise RuntimeError(f'{codec}: literal 0x{value:x} missing from builder 0x{function:x}; decoded={positions}')

    for si, spc, sreg in positions[0x1680]:
        for di, dpc, dreg in positions[0x2DF0]:
            for li, lpc, lreg in positions[0x5C0]:
                if lreg != 2:
                    continue
                lo, hi = min(si,di,li), max(si,di,li)
                if hi - lo > 24:
                    continue
                window = words[max(0,lo-5):min(len(words),hi+16)]
                src_add = next((pc for pc,w in window if (a := base.add_reg_x(w)) and a[0] == 1 and a[2] == sreg), None)
                dst_add = next((pc for pc,w in window if (a := base.add_reg_x(w)) and a[0] == 0 and a[2] == dreg), None)
                calls = [(pc,base.bl_target(pc,w)) for pc,w in window if base.bl_target(pc,w)]
                if src_add and dst_add and calls:
                    return function, (spc,dpc,lpc,src_add,dst_add,calls[0][0],calls[0][1])
    raise RuntimeError(f'{codec}: effective session+0x1680 -> command+0x2df0 len 0x5c0 copy not proven')


base.movz = movz
base.inspect_host_builder = inspect_host_builder

if __name__ == '__main__':
    base.main()
