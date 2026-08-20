#!/usr/bin/env python3
"""Create an offline component-level matrix from BuildManifest.plist.

No device communication, signing, exploit execution, or restore operation is
performed. The output deliberately distinguishes observed manifest metadata
from compatibility conclusions that require independent evidence.
"""
from __future__ import annotations
import argparse, json, plistlib
from pathlib import Path

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

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest", type=Path)
    ap.add_argument("--device", default="iPhone14,6")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    with args.manifest.open("rb") as f:
        m = plistlib.load(f)
    identities = m.get("BuildIdentities", [])
    rows = []
    for idx, identity in enumerate(identities):
        info = identity.get("Info", {}) if isinstance(identity, dict) else {}
        if info.get("ProductType") != args.device:
            continue
        manifest = identity.get("Manifest", {})
        for name, meta in sorted(manifest.items()):
            if not isinstance(meta, dict):
                meta = {}
            rows.append({
                "identity": idx,
                "component": name,
                "role": role(name),
                "path": meta.get("Info", {}).get("Path") if isinstance(meta.get("Info"), dict) else None,
                "digest": (meta.get("Info", {}) or {}).get("Digest") if isinstance(meta.get("Info"), dict) else None,
                "observed": True,
                "compatibility": "UNKNOWN",
                "authorization": "NOT_EVALUATED",
                "evidence_needed": "independent A15 compatibility evidence",
            })
    report = {
        "target": {"device": args.device, "version": m.get("ProductVersion"), "build": m.get("ProductBuildVersion")},
        "identity_count": len(identities),
        "component_count": len(rows),
        "components": rows,
        "note": "UNKNOWN compatibility is intentional; manifest presence does not establish restore authorization or boot compatibility.",
    }
    text = json.dumps(report, indent=2, sort_keys=True, default=lambda x: x.hex() if isinstance(x, bytes) else str(x))
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if rows else 1

if __name__ == "__main__":
    raise SystemExit(main())
