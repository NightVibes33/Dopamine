#!/usr/bin/env python3
"""Prove beta3 selector width/height -> LRB size -> surface allocation.

Exact-target validator for iPhone17,3 iOS 27 beta3 24A5380h, paired with the
beta4 LRB hardening marker. Static/offline only; no trigger values are derived.
"""
import struct
import sys
from pathlib import Path

from ave_hardening_family_rank import MachO, decode_bl_target

WIDTH_LOAD = 0xFFFFFFF00880F65C
HEIGHT_LOAD = 0xFFFFFFF00880F660
PAIR_SAVE = 0xFFFFFFF00880F664
PAIR_RELOAD = 0xFFFFFFF00880FBDC
WIDTH_MOVE = 0xFFFFFFF00880FCE8
HEIGHT_MOVE = 0xFFFFFFF00880FD34
ARG3_MOVE = 0xFFFFFFF00880FDB0
ARG4_MOVE = 0xFFFFFFF00880FDB4
LRB_CALL = 0xFFFFFFF00880FDC8
LRB_RESULT_STORE = 0xFFFFFFF00880FDCC
ALLOC_SIZE_LOAD = 0xFFFFFFF0087DDA28
EXISTING_SIZE_CALL = 0xFFFFFFF0087DDAC0
EXISTING_SIZE_COMPARE = 0xFFFFFFF0087DDAC4
ALLOC_ARG4_MOVE = 0xFFFFFFF0087DDB10
ALLOC_CALL = 0xFFFFFFF0087DDB1C
SURFACE_CREATE = 0xFFFFFFF0087E55F0

EXPECTED_WORDS = {
    WIDTH_LOAD: 0xB956BF89,       # ldr w9, [x28, #0x16bc]
    HEIGHT_LOAD: 0xB956C388,      # ldr w8, [x28, #0x16c0]
    PAIR_SAVE: 0x291A23E9,        # stp w9, w8, [sp, #0xd0]
    PAIR_RELOAD: 0x295A57F4,      # ldp w20, w21, [sp, #0xd0]
    WIDTH_MOVE: 0xAA1403FB,       # mov x27, x20
    HEIGHT_MOVE: 0xAA1503FA,      # mov x26, x21
    ARG3_MOVE: 0xAA1B03E3,        # mov x3, x27
    ARG4_MOVE: 0xAA1A03E4,        # mov x4, x26
    LRB_RESULT_STORE: 0xB9031E60, # str w0, [x19, #0x31c]
    ALLOC_SIZE_LOAD: 0xB9431D77,   # ldr w23, [x11, #0x31c]
    EXISTING_SIZE_COMPARE: 0x6B17001F, # cmp w0, w23
    ALLOC_ARG4_MOVE: 0xAA1703E4,   # mov x4, x23
}


def va_to_fileoff(macho, va):
    for segment in macho.segments:
        if segment["vmaddr"] <= va < segment["vmaddr"] + segment["vmsize"]:
            return segment["fileoff"] + va - segment["vmaddr"]
    raise RuntimeError(f"cannot map VA 0x{va:x}")


def word_at(macho, va):
    return struct.unpack_from("<I", macho.data, va_to_fileoff(macho, va))[0]


def find_lrb_index(beta4):
    indices = set()
    for string_va, _ in beta4.exact_strings_containing("LRB size overflow"):
        for reference in beta4.xrefs_to_va(string_va):
            index, _ = beta4.function_for_va(reference)
            if index is not None:
                indices.add(index)
    if len(indices) != 1:
        raise RuntimeError(
            f"expected one LRB hardening function, found {sorted(indices)}"
        )
    return next(iter(indices))


def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: ave_lrb_flow_map.py <beta3-AppleAVE2> <beta4-AppleAVE2> <output.md>"
        )

    beta3 = MachO(sys.argv[1])
    beta4 = MachO(sys.argv[2])
    index = find_lrb_index(beta4)
    if index >= len(beta3.functions):
        raise RuntimeError("LRB function index missing from beta3")

    lrb3 = beta3.functions[index]
    lrb4 = beta4.functions[index]

    for va, expected in EXPECTED_WORDS.items():
        actual = word_at(beta3, va)
        if actual != expected:
            raise RuntimeError(
                f"beta3 proof word mismatch at 0x{va:x}: "
                f"got 0x{actual:08x}, expected 0x{expected:08x}"
            )

    lrb_call_target = decode_bl_target(LRB_CALL, word_at(beta3, LRB_CALL))
    if lrb_call_target != lrb3:
        raise RuntimeError(
            f"LRB call target mismatch: 0x{lrb_call_target:x} != 0x{lrb3:x}"
        )

    create_target = decode_bl_target(ALLOC_CALL, word_at(beta3, ALLOC_CALL))
    if create_target != SURFACE_CREATE:
        raise RuntimeError(f"surface-create target mismatch: 0x{create_target:x}")

    existing_size_target = decode_bl_target(
        EXISTING_SIZE_CALL, word_at(beta3, EXISTING_SIZE_CALL)
    )

    lines = [
        "# AppleAVE2 LRB source-to-allocation proof",
        "",
        "Static/offline validation for iPhone17,3 iOS 27 beta3 `24A5380h`. No trigger values are generated.",
        "",
        f"- beta4 `LRB size overflow` hardening maps to function index `{index}`; beta3 LRB calculator `0x{lrb3:x}`, beta4 counterpart `0x{lrb4:x}`.",
        f"- selector/session width `+0x16bc` loads at `0x{WIDTH_LOAD:x}` and height `+0x16c0` at `0x{HEIGHT_LOAD:x}`.",
        f"- the pair is preserved through stack save/reload and moved into argument 3/4 immediately before the LRB call at `0x{LRB_CALL:x}`.",
        f"- LRB returns a required size that is stored in surface descriptor `+0x31c` at `0x{LRB_RESULT_STORE:x}`.",
        f"- surface management reloads `+0x31c` at `0x{ALLOC_SIZE_LOAD:x}`, compares an existing surface size from helper `0x{existing_size_target:x}` against that requirement at `0x{EXISTING_SIZE_COMPARE:x}`, and passes the required LRB size as argument 4 to surface create/replacement `0x{SURFACE_CREATE:x}` via call `0x{ALLOC_CALL:x}`.",
        "",
        "## Conclusion",
        "",
        "LRB now has an instruction-level source -> pre-hardening sizing -> concrete allocation-size chain. This materially advances it beyond patch-diff triage.",
        "",
        "The next unresolved control is downstream: identify the allocated LRB surface in the firmware/buffer-set handoff and determine whether its actual backing size is propagated and enforced before any firmware or hardware consumer uses LRB-derived geometry/lengths. CodedData remains the negative control for what a downstream actual-size bound looks like.",
        "",
        "This report does not demonstrate corruption, does not derive a triggering dimension pair, and does not establish a usable kernel primitive.",
    ]

    Path(sys.argv[3]).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
