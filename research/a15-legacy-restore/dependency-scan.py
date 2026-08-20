#!/usr/bin/env python3
"""Static dependency scanner for publicly available restore-tool source.

The scanner is intentionally limited to source-tree inventory and textual
reference analysis. It does not execute exploit code, patch firmware, talk to
a device, or implement a restore-security bypass.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PATTERNS = {
    "hardware_generation": [r"A7", r"A8", r"A9", r"A10", r"A11", r"A12", r"A13", r"A15", r"iPhone1[12],", r"iPhone14,6"],
    "restore_chain": [r"iBoot", r"iBEC", r"iBSS", r"LLB", r"BuildManifest", r"futurerestore", r"idevicerestore"],
    "sep": [r"SEP", r"sep-firmware", r"seprmvr64"],
    "boot_mode": [r"DFU", r"Recovery", r"restore"],
    "version_logic": [r"ProductVersion", r"ProductBuildVersion", r"ECID", r"nonce", r"generator"],
}

EXTENSIONS = {".c", ".h", ".m", ".mm", ".cpp", ".hpp", ".sh", ".py", ".plist", ".md", ".txt"}


def scan(root: Path):
    results = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in EXTENSIONS:
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        hits = {}
        for category, patterns in PATTERNS.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, text, re.I):
                    matches.append(pattern)
            if matches:
                hits[category] = matches
        if hits:
            results.append({"file": str(path.relative_to(root)), "categories": hits})
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="local source tree to inspect")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    results = scan(args.source)
    report = {
        "scope": "static source inventory",
        "device_modification": False,
        "exploit_execution": False,
        "files_with_references": results,
        "summary": {category: sum(category in r["categories"] for r in results) for category in PATTERNS},
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    print(text)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
