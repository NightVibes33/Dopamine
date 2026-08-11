#!/usr/bin/env python3
"""Map AppleAVE2 user-client open-time policy from an extracted KEXT.

Static only: this tool never opens an IOKit service or calls an external method.
It inventories exact return-code construction, policy strings, and call edges so
that an analyst can identify newUserClient/Create without guessing at runtime.
"""
import re
import struct
import sys
from pathlib import Path

from ave_userclient_map import MachO, u32

RETURNS = {
    0xE00002BD: "kIOReturnNoMemory",
    0xE00002E2: "kIOReturnNotPermitted",
    0xE00002C0: "kIOReturnSuccess",
}
KEYWORDS = ("userclient", "user client", "entitlement", "not permitted", "permission", "memory")


def words(macho, start):
    end = macho.function_end(start)
    begin = macho.va_to_fileoff(start)
    finish = macho.va_to_fileoff(end)
    if begin is None:
        return []
    if finish is None:
        finish = int(macho.text_exec["fileoff"] + macho.text_exec["filesize"])
    return [(macho.fileoff_to_va(off), u32(macho.data, off)) for off in range(begin, finish, 4)]


def decode_mov_wide(word):
    # MOVZ/MOVK (32-bit). Return operation, destination, 16-bit immediate, shift.
    masked = word & 0x7F800000
    if masked == 0x12800000:
        op = "movn"
    elif masked == 0x52800000:
        op = "movz"
    elif masked == 0x72800000:
        op = "movk"
    else:
        return None
    return op, word & 31, (word >> 5) & 0xFFFF, ((word >> 21) & 1) * 16


def return_constants(insns):
    regs = {}
    hits = []
    for pc, word in insns:
        decoded = decode_mov_wide(word)
        if decoded:
            op, reg, imm, shift = decoded
            if op == "movn":
                regs[reg] = (~(imm << shift)) & 0xFFFFFFFF
            elif op == "movz":
                regs[reg] = (imm << shift) & 0xFFFFFFFF
            elif reg in regs:
                mask = 0xFFFF << shift
                regs[reg] = (regs[reg] & ~mask) | (imm << shift)
            if reg == 0 and regs.get(0) in RETURNS:
                hits.append((pc, regs[0], RETURNS[regs[0]]))
        # RET. Record the most recent exact w0 construction in this basic window.
        if word == 0xD65F03C0 and regs.get(0) in RETURNS:
            hits.append((pc, regs[0], RETURNS[regs[0]]))
        # Calls and unconditional branches invalidate our deliberately local model.
        if word & 0xFC000000 in (0x94000000, 0x14000000):
            regs.clear()
    return sorted(set(hits))


def interesting_strings(macho, start):
    rows = []
    for pc, value in macho.string_refs_in_function(start):
        lower = value.lower()
        if any(keyword in lower for keyword in KEYWORDS):
            rows.append((pc, value))
    return rows


def direct_predecessors(macho):
    result = {}
    for source in macho.functions:
        for target in macho.direct_calls(source):
            result.setdefault(target, []).append(source)
    return result


def emit(path, label):
    macho = MachO(path)
    preds = direct_predecessors(macho)
    candidates = []
    for index, function in enumerate(macho.functions):
        insns = words(macho, function)
        returns = return_constants(insns)
        strings = interesting_strings(macho, function)
        if returns or strings:
            candidates.append((index, function, insns, returns, strings))

    out = [
        f"# AppleAVE2 open-contract map — {label}", "",
        "Static exact-binary evidence only; no IOKit service or selector was invoked.", "",
        f"- functions inspected: `{len(macho.functions)}`",
        f"- candidate functions: `{len(candidates)}`", "",
    ]
    for index, function, insns, returns, strings in candidates:
        out += [f"## function `{index}` / `0x{function:x}`", ""]
        for pc, value, name in returns:
            out.append(f"- exact return construction: `{name}` / `0x{value:08x}` near `0x{pc:x}`")
        for pc, value in strings:
            safe = re.sub(r"[\r\n`]+", " ", value)
            out.append(f"- policy/user-client string at `0x{pc:x}`: `{safe}`")
        callers = preds.get(function, [])
        if callers:
            out.append("- direct callers: " + ", ".join(f"`0x{va:x}`" for va in callers[:24]))
        out += ["", "```text"]
        marked = {pc for pc, _, _ in returns} | {pc for pc, _ in strings}
        for i, (pc, word) in enumerate(insns):
            if pc not in marked:
                continue
            for near_pc, near_word in insns[max(0, i - 6):min(len(insns), i + 7)]:
                out.append(f"0x{near_pc:x}: 0x{near_word:08x}")
            out.append("...")
        out += ["```", ""]

    out += [
        "## Disposition", "",
        "Candidates are evidence anchors, not automatically newUserClient. Identity requires a call/register trace from the IOService open wrapper into the candidate before any runtime initialization test is justified.",
    ]
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: ave_open_contract_map.py <AppleAVE2> <label> <output.md>")
    report = emit(sys.argv[1], sys.argv[2])
    Path(sys.argv[3]).write_text(report)
    print(report)


if __name__ == "__main__":
    main()
