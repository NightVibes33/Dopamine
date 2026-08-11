#!/usr/bin/env python3
"""Prove selector-4 geometry crosses the AppleAVE2 host -> H17 init IPC boundary.

Static/offline validation only. No IOKit calls, no triggering dimensions, and no
memory-corruption attempt.
"""
import struct
import sys
from pathlib import Path

import ave_dimension_flow_map as dimension_flow
import ave_lfs_geometry_provenance as base

LC_SYMTAB = 0x2


def u32(data, off): return struct.unpack_from('<I', data, off)[0]
def u64(data, off): return struct.unpack_from('<Q', data, off)[0]
def signed(v, bits):
    sign = 1 << (bits - 1)
    return v - (1 << bits) if v & sign else v


def movz(word):
    # MOVZ W/X; returned value is valid for the small immediates used here.
    if word & 0x7F800000 in (0x52800000, 0xD2800000):
        return word & 31, ((word >> 5) & 0xFFFF) << (((word >> 21) & 3) * 16)
    return None


def add_reg_x(word):
    if word & 0xFF200000 == 0x8B000000 and ((word >> 10) & 0x3F) == 0:
        return word & 31, (word >> 5) & 31, (word >> 16) & 31
    return None


def add_imm_x(word):
    if word & 0xFF000000 == 0x91000000:
        imm = (word >> 10) & 0xFFF
        if (word >> 22) & 1: imm <<= 12
        return word & 31, (word >> 5) & 31, imm
    return None


def mov_x(word):
    if word & 0xFFE0FFE0 == 0xAA0003E0:
        return word & 31, (word >> 16) & 31
    return None


def ldr_x(word):
    if word & 0xFFC00000 == 0xF9400000:
        return word & 31, (word >> 5) & 31, ((word >> 10) & 0xFFF) * 8
    return None


def ldr_w(word):
    if word & 0xFFC00000 == 0xB9400000:
        return word & 31, (word >> 5) & 31, ((word >> 10) & 0xFFF) * 4
    return None


def stp_x(word):
    if word & 0xFFC00000 == 0xA9000000:
        return word & 31, (word >> 10) & 31, (word >> 5) & 31, signed((word >> 15) & 0x7F, 7) * 8
    return None


def bl_target(pc, word):
    if word & 0xFC000000 != 0x94000000:
        return None
    return (pc + (signed(word & 0x03FFFFFF, 26) << 2)) & 0xFFFFFFFFFFFFFFFF


def inspect_host_builder(kext, flow, codec):
    marker = f'AVE_CHM_MakeFwCmd_Start_{codec}'
    funcs = kext.function_referencing(marker)
    if len(funcs) != 1:
        raise RuntimeError(f'{codec} start builder ambiguous: {funcs}')
    function = funcs[0]
    words = kext.words(function)

    constants = {}
    for i, (pc, word) in enumerate(words):
        mv = movz(word)
        if mv and mv[1] in (flow['session_copy_offset'], flow['session_copy_length'], 0x2DF0):
            constants.setdefault(mv[1], []).append((i, pc, mv[0]))

    for needed in (flow['session_copy_offset'], flow['session_copy_length'], 0x2DF0):
        if needed not in constants:
            raise RuntimeError(f'{codec}: constant 0x{needed:x} missing')

    candidates = []
    for src_i, src_pc, src_reg in constants[flow['session_copy_offset']]:
        for dst_i, dst_pc, dst_reg in constants[0x2DF0]:
            for len_i, len_pc, len_reg in constants[flow['session_copy_length']]:
                lo = min(src_i, dst_i, len_i)
                hi = max(src_i, dst_i, len_i)
                if hi - lo > 24:
                    continue
                window = words[max(0, lo-4):min(len(words), hi+18)]
                src_add = next((pc for pc,w in window if (a := add_reg_x(w)) and a[0] == 1 and a[2] == src_reg), None)
                dst_add = next((pc for pc,w in window if (a := add_reg_x(w)) and a[0] == 0 and a[2] == dst_reg), None)
                has_len = any(movz(w) == (2, flow['session_copy_length']) for _,w in window)
                call = next(((pc, bl_target(pc,w)) for pc,w in window if bl_target(pc,w)), None)
                if src_add and dst_add and has_len and call:
                    candidates.append((src_pc, dst_pc, len_pc, src_add, dst_add, call[0], call[1]))
    if not candidates:
        raise RuntimeError(f'{codec}: session+0x{flow["session_copy_offset"]:x} -> command+0x2df0 copy not proven')
    return function, candidates[0]


def all_symbols(path):
    data = Path(path).read_bytes()
    off = 32
    symtab = None
    for _ in range(u32(data, 16)):
        cmd = u32(data, off)
        size = u32(data, off + 4)
        if cmd == LC_SYMTAB:
            symtab = (u32(data, off+8), u32(data, off+12), u32(data, off+16), u32(data, off+20))
        off += size
    if symtab is None:
        raise RuntimeError('firmware symtab missing')
    symoff, nsyms, stroff, strsize = symtab
    strings = data[stroff:stroff+strsize]
    out = []
    for i in range(nsyms):
        no = symoff + i*16
        strx = u32(data, no)
        if strx >= len(strings): continue
        end = strings.find(b'\0', strx)
        if end < 0: continue
        name = strings[strx:end].decode(errors='replace')
        value = u64(data, no+8)
        if value: out.append((value, name))
    return data, out


def one_symbol(symbols, marker):
    matches = [(v,n) for v,n in symbols if marker in n]
    if len(matches) != 1:
        raise RuntimeError(f'{marker}: symbol ambiguity {matches[:8]}')
    return matches[0]


def inspect_firmware(path):
    fw = base.FirmwareMachO(path)
    data, symbols = all_symbols(path)
    init, _ = one_symbol(symbols, 'COFController4InitE14_E_AVE_EncType')
    process, _ = one_symbol(symbols, 'COFController11ProcessInitEPv')
    initenc, _ = one_symbol(symbols, 'COFController22InitEncodingParametersEPv')
    vtable, _ = one_symbol(symbols, 'ZTV13COFController')

    init_words = fw.words(init)
    # x25 = [x2] is the firmware command base. Prove 0x2df0 is added to that
    # base and stored as the first pointer at local command-info +8 (sp+0x28).
    cmd_base_reg = None
    for _, word in init_words[:24]:
        ld = ldr_x(word)
        if ld and ld[1] == 2 and ld[2] == 0:
            cmd_base_reg = ld[0]
            break
    if cmd_base_reg is None:
        raise RuntimeError('COF Init command-base load missing')

    offset_regs = [mv[0] for _,w in init_words if (mv := movz(w)) and mv[1] == 0x2DF0]
    ptr_reg = None
    add_pc = None
    for pc, word in init_words:
        add = add_reg_x(word)
        if add and add[1] == cmd_base_reg and add[2] in offset_regs:
            ptr_reg = add[0]
            add_pc = pc
            break
    if ptr_reg is None:
        raise RuntimeError('COF Init command+0x2df0 pointer construction missing')

    local_store = None
    for pc, word in init_words:
        stp = stp_x(word)
        if stp and stp[0] == ptr_reg and stp[2] == 31 and stp[3] == 0x28:
            local_store = pc
            break
    if local_store is None:
        raise RuntimeError('COF Init pInitParams local +8 store missing')
    local_arg = next((pc for pc,w in init_words if add_imm_x(w) == (1,31,0x20)), None)
    if local_arg is None:
        raise RuntimeError('COF Init local command-info argument missing')

    # Resolve the two virtual calls from the COF vtable. The object vptr points
    # 0x10 bytes into the vtable, so slots +0x130/+0x160 live at +0x140/+0x170.
    def read_qword_va(va):
        off = fw.va_to_fileoff(va)
        if off is None: raise RuntimeError(f'vtable VA 0x{va:x} not file-backed')
        return u64(data, off)
    process_slot = read_qword_va(vtable + 0x140) & 0xFFFFFFFF
    initenc_slot = read_qword_va(vtable + 0x170) & 0xFFFFFFFF
    if process_slot != (process & 0xFFFFFFFF):
        raise RuntimeError(f'COF vtable +0x130 does not resolve ProcessInit: 0x{process_slot:x}')
    if initenc_slot != (initenc & 0xFFFFFFFF):
        raise RuntimeError(f'COF vtable +0x160 does not resolve InitEncodingParameters: 0x{initenc_slot:x}')

    process_words = fw.words(process)
    if not any(mov_x(w) == (19,1) for _,w in process_words[:16]):
        raise RuntimeError('ProcessInit does not preserve incoming command-info pointer')
    if not any(mov_x(w) == (1,19) for _,w in process_words):
        raise RuntimeError('ProcessInit does not pass the same pointer to its init-parameter virtual call')
    if not any(add_imm_x(w) == (16,16,0x160) for _,w in process_words):
        raise RuntimeError('ProcessInit virtual slot +0x160 missing')

    enc_words = fw.words(initenc)
    if not any(mov_x(w) == (19,1) for _,w in enc_words[:20]):
        raise RuntimeError('InitEncodingParameters does not preserve arg1')
    pinit_regs = [ld[0] for _,w in enc_words if (ld := ldr_x(w)) and ld[1] == 19 and ld[2] == 8]
    if not pinit_regs:
        raise RuntimeError('InitEncodingParameters pInitParams = arg1+8 load missing')
    preg = pinit_regs[0]
    width_load = next((pc for pc,w in enc_words if (ld := ldr_w(w)) and ld[1] == preg and ld[2] == 0x3C), None)
    height_load = next((pc for pc,w in enc_words if (ld := ldr_w(w)) and ld[1] == preg and ld[2] == 0x40), None)
    if width_load is None or height_load is None:
        raise RuntimeError('H17 pInitParams +0x3c/+0x40 geometry loads missing')

    return {
        'init': init, 'process': process, 'initenc': initenc, 'vtable': vtable,
        'cmd_add': add_pc, 'local_store': local_store, 'local_arg': local_arg,
        'width_load': width_load, 'height_load': height_load,
    }


def analyze(k3_path, k4_path, fw3_path, fw4_path):
    flow = dimension_flow.analyze(k3_path, k4_path)
    if flow['session_copy_offset'] != 0x1680 or flow['session_copy_length'] != 0x5C0:
        raise RuntimeError(f'unexpected selector4 session block: +0x{flow["session_copy_offset"]:x}, len 0x{flow["session_copy_length"]:x}')
    if (flow['request_width'] - flow['request_substructure'], flow['request_height'] - flow['request_substructure']) != (0x3C,0x40):
        raise RuntimeError('selector4 geometry relative offsets changed')

    host = {}
    for label, path in [('beta3',k3_path), ('beta4',k4_path)]:
        k = base.KextMachO(path)
        host[label] = {}
        for codec in ('AVC','HEVC','AV1'):
            host[label][codec] = inspect_host_builder(k, flow, codec)

    fw3 = inspect_firmware(fw3_path)
    fw4 = inspect_firmware(fw4_path)
    return flow, host, fw3, fw4


def main():
    if len(sys.argv) != 6:
        raise SystemExit('usage: ave_lfs_cross_ipc_map.py <b3-kext> <b4-kext> <b3-fw> <b4-fw> <output.md>')
    flow, host, fw3, fw4 = analyze(*sys.argv[1:5])
    cmd_width = 0x2DF0 + 0x3C
    cmd_height = 0x2DF0 + 0x40
    out = [
        '# AppleAVE2 selector-4 -> H17 pInitParams cross-IPC map', '',
        'Static/offline validation only. No triggering dimension values are produced.', '',
        '## Exact field flow', '',
        f"- selector-4 request substructure starts at `+0x{flow['request_substructure']:x}`",
        f"- request width/height: `+0x{flow['request_width']:x}` / `+0x{flow['request_height']:x}` = substructure-relative `+0x3c/+0x40`",
        f"- request block is copied unchanged to session `+0x{flow['session_copy_offset']:x}`, length `0x{flow['session_copy_length']:x}`",
        f"- session width/height therefore live at `+0x{flow['session_width']:x}` / `+0x{flow['session_height']:x}`",
        '- beta3 and beta4 AVC/HEVC/AV1 start-command builders each copy that same session `+0x1680`, length `0x5c0`, to firmware command `+0x2df0`',
        f"- firmware command width/height are therefore `+0x{cmd_width:x}` / `+0x{cmd_height:x}`", '',
        '## H17 parser proof', '',
        f"- beta3 `COFController::Init`: `0x{fw3['init']:x}` constructs command `+0x2df0` at `0x{fw3['cmd_add']:x}` and stores it as local command-info `+0x8` at `0x{fw3['local_store']:x}`",
        f"- COF vtable dispatch resolves that local structure through `ProcessInit` (`0x{fw3['process']:x}`) to `InitEncodingParameters` (`0x{fw3['initenc']:x}`)",
        f"- `InitEncodingParameters` loads `pInitParams = command-info +0x8`, then reads width/height at pInitParams `+0x3c/+0x40` (`0x{fw3['width_load']:x}` / `0x{fw3['height_load']:x}`)",
        '- beta4 reproduces the same field-flow structure after code-address movement', '',
        '## Conclusion', '',
        '**The cross-IPC geometry mapping is proven:** selector-4 request `+0x374/+0x378` -> session `+0x16bc/+0x16c0` -> firmware command `+0x2e2c/+0x2e30` -> H17 `pInitParams +0x3c/+0x40`.', '',
        'This closes the prior field-equivalence gap for the LFSOutput analysis. It still does not prove memory corruption or produce a useful kernel primitive, and this validator intentionally does not solve for a triggering dimension pair.'
    ]
    Path(sys.argv[5]).write_text('\n'.join(out) + '\n')
    print('\n'.join(out))

if __name__ == '__main__':
    main()
