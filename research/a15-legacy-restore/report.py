#!/usr/bin/env python3
"""Generate a structured, offline BuildManifest report.

This tool performs IPSW metadata analysis only. It does not communicate with
a device, request restore authorization, resign components, or alter payloads.
"""
from __future__ import annotations

import argparse
import json
import plistlib
from pathlib import Path
from typing import Any

KEYWORDS = {
    "iboot": ("iBoot",),
    "sep": ("SEP", "seprom"),
    "ramdisk": ("ramdisk", "RestoreRamdisk"),
    "kernel": ("kernelcache", "KernelCache"),
    "devicetree": ("DeviceTree", "devicetree"),
    "firmware": ("Firmware", "firmware"),
    "baseband": ("Baseband", "baseband"),
    "cryptex": ("Cryptex", "cryptex"),
}


def classify(name: str) -> str:
    for category, terms in KEYWORDS.items():
        if any(term.lower() in name.lower() for term in terms):
            return category
    return "other"


def load(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        value = plistlib.load(handle)
    if not isinstance(value, dict):
        raise ValueError("manifest root is not a dictionary")
    return value


def serialise(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): serialise(v) for k, v in value.items()}
    if isinstance(value, list):
        return [serialise(v) for v in value]
    return value


def build_report(manifest: dict[str, Any], device: str) -> dict[str, Any]:
    identities = manifest.get("BuildIdentities", [])
    if not isinstance(identities, list):
        identities = []

    matches = []
    for index, identity in enumerate(identities):
        if not isinstance(identity, dict):
            continue
        info = identity.get("Info", {})
        if not isinstance(info, dict):
            info = {}
        product_type = info.get("ProductType")
        if product_type == device:
            entries = identity.get("Manifest", {})
            components = []
            if isinstance(entries, dict):
                for name, metadata in sorted(entries.items()):
                    item = {"name": name, "category": classify(str(name))}
                    if isinstance(metadata, dict):
                        item["metadata"] = serialise(metadata)
                    components.append(item)
            matches.append({"index": index, "info": serialise(info), "components": components})

    return {
        "manifest": {
            "ProductVersion": manifest.get("ProductVersion"),
            "ProductBuildVersion": manifest.get("ProductBuildVersion"),
            "ProductType": manifest.get("ProductType"),
            "identity_count": len(identities),
        },
        "requested_device": device,
        "matching_identities": matches,
        "result": "MANIFEST_IDENTITY_FOUND" if matches else "NO_DIRECT_DEVICE_IDENTITY",
        "authorization": "NOT_EVALUATED",
        "boot_compatibility": "NOT_EVALUATED",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--device", default="iPhone14,6")
    parser.add_argument("--json", type=Path, help="write JSON report")
    parser.add_argument("--text", type=Path, help="write human-readable report")
    args = parser.parse_args()

    report = build_report(load(args.manifest), args.device)
    payload = json.dumps(report, indent=2, sort_keys=True)
    print(payload)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(payload + "\n", encoding="utf-8")
    if args.text:
        args.text.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"Device: {args.device}",
            f"Version: {report['manifest'].get('ProductVersion')}",
            f"Build: {report['manifest'].get('ProductBuildVersion')}",
            f"Identities: {report['manifest']['identity_count']}",
            f"Matching identities: {len(report['matching_identities'])}",
            f"Result: {report['result']}",
            "Authorization: NOT EVALUATED",
            "Boot compatibility: NOT EVALUATED",
        ]
        args.text.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return 0 if report["matching_identities"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
