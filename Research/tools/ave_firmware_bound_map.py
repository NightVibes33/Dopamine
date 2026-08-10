#!/usr/bin/env python3
"""Offline validator for AVE firmware CodedData size-bound handling.

The tool compares iPhone17,3 beta3/beta4 AppleAVE2FW_H17 payloads. It proves
that AVC/HEVC firmware copy an incoming coded-data size into controller state,
program that bound in SetTranscode before encoding, and compare produced sizes
against the same state field in ProcessTranscodeDone.

Static analysis only. No device access and no trigger values are generated.
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

CODECS = {
    "AVC": {
        "start": "__ZN14CAVCController21ProcessTranscodeStartEPv",
        "set": "__ZN14CAVCController12SetTranscodeEP26CAVEControllerAvcEncodeCmd",
        "done": "__ZN14CAVCController20ProcessTranscodeDoneEP30CAVEControllerTranscodeDoneCmd",
    },
    "HEVC": {
        "start": "__ZN15CHEVCController21ProcessTranscodeStartEPv",
        "set": "__ZN15CHEVCController12SetTranscodeEj",
        "done": "__ZN15CHEVCController20ProcessTranscodeDoneEP30CAVEControllerTranscodeDoneCmd",
    },
}

STATE_SIZE_OFFSET = 0x3E84
PRODUCED_COMPONENT_OFFSETS = (0x3E58, 0x3E5C, 0x3E80)


def objdump_prefix():
    direct = shutil.which("llvm-objdump")
    if direct:
        return [direct]
    xcrun = shutil.which("xcrun")
    if xcrun:
        resolved = subprocess.check_output(
            [xcrun, "--find", "llvm-objdump"], text=True
        ).strip()
        if resolved:
            return [resolved]
    raise RuntimeError("llvm-objdump not found")


def run_objdump(path, *args):
    cmd = objdump_prefix() + list(args) + [str(path)]
    return subprocess.check_output(cmd, text=True, errors="replace")


def symbol_address(path, symbol):
    text = run_objdump(path, "--syms")
    for line in text.splitlines():
        if line.rstrip().endswith(" " + symbol):
            return int(line.split()[0], 16)
    raise RuntimeError(f"symbol not found: {symbol}")


def disassemble_symbol(path, symbol):
    return run_objdump(
        path, "-d", "--arch=arm64", f"--disassemble-symbols={symbol}"
    )


def instruction_rows(text):
    rows = []
    for line in text.splitlines():
        match = re.match(
            r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z0-9.]+)\s*(.*)$", line
        )
        if match:
            rows.append(
                (
                    int(match.group(1), 16),
                    match.group(2),
                    match.group(3).strip(),
                )
            )
    return rows


def parse_ldr_w(operand):
    match = re.match(r"w(\d+), \[x(\d+), #0x([0-9a-f]+)\]$", operand)
    if not match:
        return None
    reg, base, offset = match.groups()
    return int(reg), int(base), int(offset, 16)


def parse_str_w(operand):
    match = re.match(r"w(\d+), \[x(\d+)(?:, #0x([0-9a-f]+))?\]$", operand)
    if not match:
        return None
    reg, base, offset = match.groups()
    return int(reg), int(base), int(offset, 16) if offset else 0


def stored_w_reg(operand):
    match = re.match(r"w(\d+), \[", operand)
    return int(match.group(1)) if match else None


def find_start_size_copy(rows):
    for index, (pc, mnemonic, operand) in enumerate(rows):
        if mnemonic != "ldr":
            continue
        load = parse_ldr_w(operand)
        if not load:
            continue
        source_reg, _, incoming_offset = load
        for pc2, mnemonic2, operand2 in rows[index + 1:index + 5]:
            if mnemonic2 != "str":
                continue
            store = parse_str_w(operand2)
            if store and store[0] == source_reg and store[2] == STATE_SIZE_OFFSET:
                return pc, pc2, source_reg, incoming_offset
    return None


def find_settranscode_size_program(rows):
    for index, (pc, mnemonic, operand) in enumerate(rows):
        if mnemonic != "ldr":
            continue
        load = parse_ldr_w(operand)
        if not load or load[2] != STATE_SIZE_OFFSET:
            continue
        source_reg = load[0]
        # The size must be consumed by a store shortly afterward. This proves
        # pre-transcode programming, but intentionally does not assign an
        # undocumented MMIO meaning to the destination register/address.
        for pc2, mnemonic2, operand2 in rows[index + 1:index + 9]:
            if mnemonic2 == "str" and stored_w_reg(operand2) == source_reg:
                return pc, pc2, source_reg
    return None


def find_done_bound_check(rows):
    wanted = set(PRODUCED_COMPONENT_OFFSETS + (STATE_SIZE_OFFSET,))
    for index in range(len(rows) - 8):
        window = rows[index:index + 12]
        loads = {}
        for pc, mnemonic, operand in window[:6]:
            if mnemonic != "ldr":
                continue
            load = parse_ldr_w(operand)
            if load and load[2] in wanted:
                loads[load[2]] = (pc, load[0])
        if set(loads) != wanted:
            continue
        add_count = sum(1 for _, mnemonic, _ in window if mnemonic == "add")
        bound_reg = loads[STATE_SIZE_OFFSET][1]
        compare = next(
            (
                (pc, operand)
                for pc, mnemonic, operand in window
                if mnemonic == "cmp" and re.search(rf"\bw{bound_reg}\b", operand)
            ),
            None,
        )
        branch = next(
            (pc for pc, mnemonic, _ in window if mnemonic == "b.ls"), None
        )
        if add_count >= 2 and compare and branch:
            return {
                "load_pcs": {offset: loads[offset][0] for offset in sorted(loads)},
                "cmp_pc": compare[0],
                "branch_pc": branch,
            }
    return None


def analyze_one(path):
    result = {}
    blob = Path(path).read_bytes()
    diagnostic = b"bitstream size overflow, buffer size: %d, bitstream size: %d"
    if diagnostic not in blob:
        raise RuntimeError(f"overflow diagnostic missing in {path}")

    for codec, symbols in CODECS.items():
        start_rows = instruction_rows(disassemble_symbol(path, symbols["start"]))
        set_rows = instruction_rows(disassemble_symbol(path, symbols["set"]))
        done_rows = instruction_rows(disassemble_symbol(path, symbols["done"]))

        start_copy = find_start_size_copy(start_rows)
        set_program = find_settranscode_size_program(set_rows)
        done_check = find_done_bound_check(done_rows)

        if not start_copy:
            raise RuntimeError(f"{codec}: incoming size -> state copy not found")
        if not set_program:
            raise RuntimeError(f"{codec}: pre-transcode state-size programming not found")
        if not done_check:
            raise RuntimeError(f"{codec}: produced-size <= bound check not found")

        result[codec] = {
            "start": symbol_address(path, symbols["start"]),
            "set": symbol_address(path, symbols["set"]),
            "done_start": symbol_address(path, symbols["done"]),
            "start_load": start_copy[0],
            "state_store": start_copy[1],
            "incoming_offset": start_copy[3],
            "set_size_load": set_program[0],
            "set_size_store": set_program[1],
            "done_check": done_check,
        }
    return result


def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: ave_firmware_bound_map.py <beta3-fw> <beta4-fw> <output.md>"
        )

    beta3 = analyze_one(sys.argv[1])
    beta4 = analyze_one(sys.argv[2])
    lines = [
        "# AVE firmware CodedData size-bound handling",
        "",
        "Static/offline comparison only. No device access or trigger values.",
        "",
    ]

    for codec in CODECS:
        old = beta3[codec]
        new = beta4[codec]
        lines += [
            f"## {codec}",
            "",
            f"- beta3 ProcessTranscodeStart: `0x{old['start']:x}`; incoming `+0x{old['incoming_offset']:x}` size load `0x{old['start_load']:x}` -> controller `+0x{STATE_SIZE_OFFSET:x}` store `0x{old['state_store']:x}`",
            f"- beta3 SetTranscode: `0x{old['set']:x}`; controller size load `0x{old['set_size_load']:x}` -> pre-transcode programming store `0x{old['set_size_store']:x}`",
            f"- beta3 ProcessTranscodeDone: `0x{old['done_start']:x}`; produced-size components `+0x{PRODUCED_COMPONENT_OFFSETS[0]:x}/+0x{PRODUCED_COMPONENT_OFFSETS[1]:x}/+0x{PRODUCED_COMPONENT_OFFSETS[2]:x}` are summed and compared with controller `+0x{STATE_SIZE_OFFSET:x}` at `0x{old['done_check']['cmp_pc']:x}`, followed by unsigned `<=` branch at `0x{old['done_check']['branch_pc']:x}`",
            f"- beta4 preserves the same three semantics (incoming size field now `+0x{new['incoming_offset']:x}`) at Start `0x{new['start']:x}`, SetTranscode `0x{new['set']:x}`, Done `0x{new['done_start']:x}`",
            "",
        ]

    lines += [
        "## Interpretation",
        "",
        "For both AVC and HEVC, the firmware consumes the supplied CodedData size before transcode and later checks the total produced bitstream size against the same controller-state bound. The post-transcode comparison is not, by itself, proof that the underlying engine cannot have written past the buffer, and this validator intentionally does not assign undocumented MMIO semantics to the pre-transcode store.",
        "",
        "Combined with the kernel-driver proof that the firmware descriptor receives the actual backing-surface size, this is strong counterevidence against treating the CodedData undersized-allocation path alone as the corruption primitive. The broader beta3->beta4 hardening family should therefore be ranked across the other affected buffer types rather than forcing CodedData into an exploit claim.",
    ]

    Path(sys.argv[3]).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
