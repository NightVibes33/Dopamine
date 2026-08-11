#!/usr/bin/env python3
"""Build an evidence-gated CVE triage ledger from exact-firmware inventories.

This tool is intentionally non-exploitative: it consumes hashes, paths, and
string inventories produced by CI. It never opens services or generates inputs.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

SEEDS = [
    {
        "id": "IOS27-CVE-43723",
        "cve": "CVE-2026-43723",
        "component": "MediaRemote",
        "primitive": "root privilege via path handling",
        "anchor": "MediaRemote executable/framework",
        "cwe": ["CWE-22"],
        "public_detail": "public minimal PoC and technical note exist",
    },
    {
        "id": "IOS27-CVE-43805",
        "cve": "CVE-2026-43805",
        "component": "IOKit",
        "primitive": "race; possible kernel-memory write",
        "anchor": None,
        "cwe": ["CWE-362"],
        "public_detail": "advisory only; vulnerable IOKit class is not public",
    },
    {
        "id": "IOS27-CVE-64751",
        "cve": "CVE-2026-64751",
        "component": "Kernel",
        "primitive": "use-after-free; possible kernel-memory write",
        "anchor": None,
        "cwe": ["CWE-416"],
        "public_detail": "advisory only; vulnerable subsystem/function is not public",
    },
]

def load(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected JSON object")
    return value

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--b3-inventory", type=Path, required=True)
    ap.add_argument("--patched-inventory", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--out-md", type=Path, required=True)
    ns = ap.parse_args()
    b3, patched = load(ns.b3_inventory), load(ns.patched_inventory)
    for label, obj in (("beta3", b3), ("patched-side", patched)):
        for key in ("build", "device", "kernel_sha256", "paths", "strings"):
            if key not in obj:
                raise SystemExit(f"{label}: missing {key}")
    if b3["device"] != "iPhone17,3" or b3["build"] != "24A5380h":
        raise SystemExit("beta3 inventory is not the authorized exact target")
    rows = []
    for seed in SEEDS:
        needle = seed["component"].lower()
        b3_hits = sorted(x for x in b3["paths"] + b3["strings"] if needle in x.lower())
        patched_hits = sorted(x for x in patched["paths"] + patched["strings"] if needle in x.lower())
        anchored = bool(seed["anchor"] and b3_hits and patched_hits)
        disposition = "candidate-present-unvalidated" if anchored else "deferred-missing-patch-anchor"
        rows.append({
            **seed,
            "source": "sandboxed app per Apple advisory",
            "sink_or_broken_control": seed["primitive"],
            "beta3_hits": b3_hits[:100],
            "patched_hits": patched_hits[:100],
            "disposition": disposition,
            "validation_recommended": True,
            "proof_gap": (
                "instruction-level vulnerable/fixed function mapping"
                if anchored else
                "public vulnerable class, subsystem, function, crash, or patch anchor"
            ),
        })
    report = {
        "schema": 1,
        "scope": {"device": b3["device"], "build": b3["build"]},
        "comparison": {"build": patched["build"], "device": patched["device"]},
        "input_sha256": {
            "beta3_inventory": sha256(ns.b3_inventory),
            "patched_inventory": sha256(ns.patched_inventory),
        },
        "safety": {
            "live_service_calls": False,
            "trigger_generation": False,
            "poc_execution": False,
            "claim_policy": "binary change alone is not attributed to a CVE",
        },
        "candidates": rows,
    }
    ns.out_json.parent.mkdir(parents=True, exist_ok=True)
    ns.out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    lines = [
        "# iPhone17,3 iOS 27 CVE triage",
        "",
        f"- Exact target: \`{b3['build']}\`",
        f"- Patched-side comparator: \`{patched['build']}\`",
        "- PoCs executed: no",
        "- Live services opened: no",
        "",
        "| Candidate | Component | Disposition | Remaining proof gap |",
        "|---|---|---|---|",
    ]
    for row in rows:
        lines.append(f"| {row['cve']} | {row['component']} | {row['disposition']} | {row['proof_gap']} |")
    lines += [
        "",
        "## Interpretation",
        "",
        "A component/path/string delta is discovery evidence only. It is not a CVE attribution,",
        "proof of vulnerability, kernel primitive, or jailbreak. Advisory-only rows stay deferred",
        "until a public patch, crash signature, class, function, or equivalent exact anchor exists.",
        "",
    ]
    ns.out_md.write_text("\n".join(lines))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
