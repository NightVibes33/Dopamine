#!/usr/bin/env python3
"""Create an offline component-level matrix from BuildManifest.plist."""
from __future__ import annotations

import argparse
import json
import plistlib
from pathlib import Path

from manifest_utils import load_profile, manifest_supports_product, matching_identities

ROLES = {
    "iboot": "boot-chain",
    "ibec": "boot-chain",
    "ibss": "boot-chain",
    "llb": "boot-chain",
    "sep": "secure-enclave",
    "restore": "restore-environment",
    "ramdisk": "restore-environment",
    "kernel": "kernel",
    "devicetree": "hardware-description",
    "baseband": "baseband",
    "firmware": "firmware",
    "cryptex": "runtime-firmware",
}


def role(name: str) -> str:
    n = name.lower()
    for key, value in ROLES.items():
        if key in n:
            return value
    return "other"


def serialise(value):
    if isinstance(value, bytes):
        return value.hex()
    return value


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest", type=Path)
    ap.add_argument("--profile", type=Path)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    with args.manifest.open("rb") as f:
        manifest_root = plistlib.load(f)
    profile = load_profile(args.profile)

    rows = []
    for idx, identity, reasons in matching_identities(manifest_root, profile):
        manifest = identity.get("Manifest", {})
        if not isinstance(manifest, dict):
            continue
        for name, meta in sorted(manifest.items()):
            if not isinstance(meta, dict):
                meta = {}
            info = meta.get("Info") if isinstance(meta.get("Info"), dict) else {}
            digest = meta.get("Digest") or info.get("Digest")
            rows.append({
                "identity": idx,
                "match_reasons": reasons,
                "component": name,
                "role": role(name),
                "path": info.get("Path"),
                "digest": serialise(digest),
                "observed": True,
                "compatibility": "UNKNOWN",
                "authorization": "NOT_EVALUATED",
                "evidence_needed": "independent A15 compatibility evidence",
            })

    supported = manifest_supports_product(manifest_root, profile["product_type"])
    report = {
        "target": profile,
        "manifest": {
            "version": manifest_root.get("ProductVersion"),
            "build": manifest_root.get("ProductBuildVersion"),
            "product_supported": supported,
            "identity_count": len(manifest_root.get("BuildIdentities", [])),
        },
        "component_count": len(rows),
        "components": rows,
        "note": "Manifest presence proves packaging for the target hardware identity only; authorization and boot compatibility remain unevaluated.",
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if supported and rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
