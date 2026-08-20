#!/usr/bin/env python3
"""Read-only string-reference labeling for ranked SecureROM hotspots.

Uses segment-accurate Ibis layouts and Capstone detail mode to resolve a small
set of common ARM64 PC-relative reference patterns (ADR, ADRP+ADD, ADRP+LDR).
The output contains printable labels and broad subsystem tags only; it does not
emit payloads, patches, or device interaction steps.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

PRINTABLE = set(range(0x20, 0x7F))
KEYWORDS = {
    "usb_dfu": ("usb", "dfu", "recovery", "usbd", "dwc", "serial"),
    "image_validation": ("image4", "img4", "im4", "manifest", "ticket", "nonce", "personalized"),
    "platform_dart": ("dart", "iommu", "dma", "platform", "chip", "soc"),
    "memory_tasking": ("heap", "malloc", "free", "alloc", "task", "stack", "panic"),
    "crypto": ("aes", "sha", "rsa", "ecid", "crypto", "hash", "digest"),
    "storage_boot": ("boot", "iboot", "sep", "nvram", "restore", "ramdisk"),
}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def region_for_vaddr(layout, addr):
    for name, r in layout.get("regions", {}).items():
        if r.get("start") is None or r.get("end") is None:
            continue
        if r["start"] <= addr < r["end"]:
            return name, r
    return None, None


def vaddr_to_file(layout, addr):
    name, r = region_for_vaddr(layout, addr)
    if not r or r.get("offset") is None:
        return name, None
    return name, r["offset"] + (addr - r["start"])


def read_cstring(data: bytes, off: int, limit=192):
    if off is None or off < 0 or off >= len(data):
        return None
    end = off
    while end < min(len(data), off + limit) and data[end] in PRINTABLE:
        end += 1
    if end - off < 4:
        return None
    if end < len(data) and data[end] != 0 and end - off < 8:
        return None
    return data[off:end].decode("ascii", "replace")


def deref_string(data: bytes, layout, addr):
    region, off = vaddr_to_file(layout, addr)
    direct = read_cstring(data, off) if off is not None else None
    if direct:
        return {"region": region, "address": addr, "file_offset": off, "string": direct, "kind": "direct"}
    if off is not None and off + 8 <= len(data):
        ptr = int.from_bytes(data[off:off+8], "little")
        pregion, poff = vaddr_to_file(layout, ptr)
        indirect = read_cstring(data, poff) if poff is not None else None
        if indirect:
            return {"region": pregion, "address": ptr, "file_offset": poff, "string": indirect, "kind": "pointer"}
    return None


def disasm_function(data: bytes, layout, file_start: int, count: int):
    text = layout["regions"]["TEXT"]
    if text.get("offset") is None:
        return []
    vstart = text["start"] + (file_start - text["offset"])
    raw = data[file_start:file_start + count * 4]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return list(md.disasm(raw, vstart))


def refs_for_function(data: bytes, layout, file_start: int, count: int):
    regs = {}
    found = []
    seen = set()
    for ins in disasm_function(data, layout, file_start, count):
        m = ins.mnemonic.lower()
        ops = ins.operands
        targets = []
        if m in ("adr", "adrp") and len(ops) >= 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
            regs[ops[0].reg] = ops[1].imm
            if m == "adr":
                targets.append((ops[1].imm, "adr"))
        elif m == "add" and len(ops) >= 3 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
            if ops[1].reg in regs:
                value = regs[ops[1].reg] + ops[2].imm
                regs[ops[0].reg] = value
                targets.append((value, "adrp_add"))
            else:
                regs.pop(ops[0].reg, None)
        elif m.startswith("ldr") and len(ops) >= 2:
            if ops[1].type == ARM64_OP_IMM:
                targets.append((ops[1].imm, "ldr_literal"))
            elif ops[1].type == ARM64_OP_MEM:
                base = ops[1].mem.base
                if base in regs:
                    targets.append((regs[base] + ops[1].mem.disp, "adrp_ldr"))
            if ops[0].type == ARM64_OP_REG:
                regs.pop(ops[0].reg, None)
        else:
            # Conservatively drop a tracked value when an instruction overwrites
            # its first register operand, except for harmless comparisons/branches.
            if ops and ops[0].type == ARM64_OP_REG and m not in ("cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz") and not m.startswith("b"):
                regs.pop(ops[0].reg, None)

        for addr, source in targets:
            item = deref_string(data, layout, addr)
            if not item:
                continue
            key = (item["address"], item["string"])
            if key in seen:
                continue
            seen.add(key)
            item["source"] = source
            found.append(item)
    return found


def tags(strings):
    blob = "\n".join(x["string"].lower() for x in strings)
    out=[]
    for tag, words in KEYWORDS.items():
        if any(w in blob for w in words):
            out.append(tag)
    return out


def annotate_side(data, layout, row, prefix):
    start = row.get(prefix + "_start")
    insns = row.get(prefix + "_insns")
    if start is None or insns is None:
        return []
    return refs_for_function(data, layout, start, insns)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("base", type=Path)
    ap.add_argument("candidate", type=Path)
    ap.add_argument("base_layout", type=Path)
    ap.add_argument("candidate_layout", type=Path)
    ap.add_argument("hotspots", type=Path)
    ap.add_argument("--output", type=Path)
    args=ap.parse_args()

    a=args.base.read_bytes(); b=args.candidate.read_bytes()
    la=load(args.base_layout); lb=load(args.candidate_layout); hot=load(args.hotspots)
    rows=[]
    for rank, row in enumerate(hot.get("ranked_text_candidates", []), 1):
        ar=annotate_side(a, la, row, "a")
        br=annotate_side(b, lb, row, "b")
        merged={x["string"] for x in ar+br}
        rows.append({
            "rank":rank,
            "priority_score":row.get("priority_score"),
            "kind":row.get("kind"),
            "a_start":row.get("a_start"),
            "b_start":row.get("b_start"),
            "a_references":ar,
            "b_references":br,
            "subsystem_tags":tags(ar+br),
            "unique_printable_labels":sorted(merged),
        })
    report={
        "candidate_count":len(rows),
        "labeled_candidate_count":sum(1 for r in rows if r["unique_printable_labels"]),
        "tagged_candidate_count":sum(1 for r in rows if r["subsystem_tags"]),
        "ranked_candidates":rows,
        "note":"Read-only string-reference heuristics are labels for static review; they do not establish function identity or exploitability."
    }
    payload=json.dumps(report,indent=2,sort_keys=True)
    print(payload)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(payload+"\n",encoding="utf-8")

if __name__=="__main__":
    main()
