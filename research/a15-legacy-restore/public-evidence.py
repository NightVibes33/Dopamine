#!/usr/bin/env python3
"""Record and verify public, non-sensitive evidence for A15 legacy-restore research.

The collector deliberately avoids exploit execution, device communication,
signing operations, firmware patching, and restore authorization requests.
It only records source metadata and checks declared local artifacts/hashes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", type=Path, default=Path("research/a15-legacy-restore/evidence-sources.json"))
    ap.add_argument("--ipsw", type=Path, help="optional local target IPSW to hash-check")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    data = json.loads(args.sources.read_text(encoding="utf-8"))
    result = {
        "target": data.get("target", {}),
        "sources": data.get("sources", []),
        "local_checks": [],
        "scope": "public metadata and local hash verification only",
    }

    if args.ipsw:
        actual = sha256_file(args.ipsw)
        expected = data.get("target", {}).get("sha256")
        result["local_checks"].append({
            "artifact": str(args.ipsw),
            "sha256": actual,
            "expected_sha256": expected,
            "matches": bool(expected and actual.lower() == expected.lower()),
        })

    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
