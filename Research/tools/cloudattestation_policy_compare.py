#!/usr/bin/env python3
"""Compare CloudAttestation policy.getter implementations without executing them."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from pathlib import Path

ANCHOR = "PCC.ComputeNodeValidator.policy.getter"
LINE = re.compile(r"^([0-9a-fA-F]{8,16})\s+([a-zA-Z][a-zA-Z0-9.]*)\s*(.*)$")
NM = re.compile(r"^([0-9a-fA-F]{8,16})\s+.*?\s(\S+)$")


@dataclass
class Fingerprint:
    path: str
    sha256: str
    address: str
    size: int
    instruction_count: int
    conditional_branches: int
    unconditional_branches: int
    calls: int
    loads: int
    stores: int
    normalized: list[str]


def run(command: list[str], *, stdin: str | None = None, timeout: int = 180) -> str:
    result = subprocess.run(command, input=stdin, text=True, capture_output=True,
                            timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr[-2000:]}")
    return result.stdout


def symbols(path: Path) -> list[tuple[int, str, str]]:
    raw = run(["nm", "-n", str(path)])
    rows: list[tuple[int, str]] = []
    for line in raw.splitlines():
        match = NM.match(line.strip())
        if match:
            rows.append((int(match.group(1), 16), match.group(2)))
    if not rows:
        raise RuntimeError(f"no symbols recovered from {path}")
    demangled = run(["xcrun", "swift-demangle", "--compact"], stdin="\n".join(name for _, name in rows))
    names = demangled.splitlines()
    if len(names) != len(rows):
        raise RuntimeError("swift-demangle output count mismatch")
    return [(address, mangled, names[index]) for index, (address, mangled) in enumerate(rows)]


def locate(path: Path, forced_address: int | None, forced_size: int | None) -> tuple[int, int]:
    rows = symbols(path)
    if forced_address is not None:
        start = forced_address
    else:
        matches = [(address, demangled) for address, _, demangled in rows
                   if "ComputeNodeValidator" in demangled and "policy.getter" in demangled]
        if len(matches) != 1:
            raise RuntimeError(f"expected one {ANCHOR} symbol in {path}, found {len(matches)}")
        start = matches[0][0]
    later = sorted(address for address, _, _ in rows if address > start)
    size = forced_size or ((later[0] - start) if later else 0)
    if not 16 <= size <= 4096:
        raise RuntimeError(f"implausible function size {size:#x} at {start:#x} in {path}")
    return start, size


def normalize(mnemonic: str, operands: str) -> str:
    m = mnemonic.lower()
    if m in {"bl", "blr"}: return "call"
    if m == "b": return "jump"
    if m.startswith("b.") or m in {"cbz", "cbnz", "tbz", "tbnz"}: return "branch:" + m
    if m.startswith("ldr") or m in {"ldp", "ldur"}: return "load:" + m
    if m.startswith("str") or m in {"stp", "stur"}: return "store:" + m
    if m in {"adr", "adrp"}: return m + ":address"
    if m in {"cmp", "cmn", "tst"}: return m
    return m


def fingerprint(path: Path, address: int | None = None, size: int | None = None) -> Fingerprint:
    start, length = locate(path, address, size)
    end = start + length
    disassembly = run(["otool", "-arch", "arm64", "-tvV", str(path)], timeout=300)
    instructions: list[tuple[str, str]] = []
    for line in disassembly.splitlines():
        match = LINE.match(line.strip())
        if not match:
            continue
        pc = int(match.group(1), 16)
        if start <= pc < end:
            instructions.append((match.group(2).lower(), match.group(3)))
    if len(instructions) < 4:
        raise RuntimeError(f"only {len(instructions)} instructions recovered at {start:#x} in {path}")
    normalized = [normalize(m, operands) for m, operands in instructions]
    return Fingerprint(
        path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        address=f"0x{start:x}", size=length, instruction_count=len(instructions),
        conditional_branches=sum(x.startswith("branch:") for x in normalized),
        unconditional_branches=normalized.count("jump"), calls=normalized.count("call"),
        loads=sum(x.startswith("load:") for x in normalized),
        stores=sum(x.startswith("store:") for x in normalized), normalized=normalized)


def similarity(a: Fingerprint, b: Fingerprint) -> float:
    return round(SequenceMatcher(None, a.normalized, b.normalized, autojunk=False).ratio(), 4)


def structural_distance(a: Fingerprint, b: Fingerprint) -> int:
    fields = ("instruction_count", "conditional_branches", "unconditional_branches", "calls", "loads", "stores")
    return sum(abs(getattr(a, field) - getattr(b, field)) for field in fields)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--vulnerable", type=Path, required=True)
    parser.add_argument("--patched", type=Path, required=True)
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument("--out-md", type=Path, required=True)
    args = parser.parse_args()
    vulnerable = fingerprint(args.vulnerable, 0x235E16F5C, 0x1C4)
    patched = fingerprint(args.patched, 0x235E02FA8, 0x1DC)
    target = fingerprint(args.target)
    vulnerable_similarity = similarity(target, vulnerable)
    patched_similarity = similarity(target, patched)
    vulnerable_distance = structural_distance(target, vulnerable)
    patched_distance = structural_distance(target, patched)
    margin = round(abs(patched_similarity - vulnerable_similarity), 4)
    if margin >= 0.08 and patched_similarity > vulnerable_similarity and patched_distance <= vulnerable_distance:
        disposition = "patched-like"
    elif margin >= 0.08 and vulnerable_similarity > patched_similarity and vulnerable_distance <= patched_distance:
        disposition = "vulnerable-like"
    else:
        disposition = "deferred-ambiguous-control-flow"
    report = {
        "schema": 1,
        "candidate": "CVE-2026-43813",
        "target": {"device": "iPhone17,3", "build": "24A5380h"},
        "references": {"vulnerable_build": "23G5057c", "patched_build": "23G5065a"},
        "anchor": ANCHOR,
        "method": "normalized static ARM64 function and structural comparison",
        "safety": {"pocs_executed": False, "crafted_inputs": False, "binaries_executed": False},
        "fingerprints": {"target": asdict(target), "vulnerable": asdict(vulnerable), "patched": asdict(patched)},
        "comparison": {
            "target_to_vulnerable_similarity": vulnerable_similarity,
            "target_to_patched_similarity": patched_similarity,
            "similarity_margin": margin,
            "target_to_vulnerable_structural_distance": vulnerable_distance,
            "target_to_patched_structural_distance": patched_distance,
        },
        "disposition": disposition,
        "identity_confirmed": disposition == "vulnerable-like",
        "proof_gap": None if disposition != "deferred-ambiguous-control-flow" else "a distinctive patch basic block or data-flow xref",
    }
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    args.out_md.write_text("\n".join([
        "# CVE-2026-43813 CloudAttestation correlation", "",
        "- Target: `iPhone17,3 / 24A5380h`", f"- Disposition: `{disposition}`",
        f"- Similarity to vulnerable `23G5057c`: `{vulnerable_similarity}`",
        f"- Similarity to patched `23G5065a`: `{patched_similarity}`",
        f"- Similarity margin: `{margin}`", f"- Structural distances (vulnerable/patched): `{vulnerable_distance}/{patched_distance}`",
        "- PoCs executed: no", "- Crafted inputs generated: no", "",
        "A `vulnerable-like` result is static implementation attribution, not proof of exploitability or a general app-signing bypass.", ""
    ]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
