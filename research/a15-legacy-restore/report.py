#!/usr/bin/env python3
"""Generate a structured offline BuildManifest report."""
from __future__ import annotations

import argparse
import json
import plistlib
from pathlib import Path
from typing import Any

from manifest_utils import load_profile, manifest_supports_product, matching_identities

KEYWORDS = {
    "iboot": ("iBoot", "iBEC", "iBSS", "LLB"),
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


def build_report(manifest: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    identities = manifest.get("BuildIdentities", [])
    if not isinstance(identities, list):
        identities = []

    matches = []
    for index, identity, reasons in matching_identities(manifest, profile):
        entries = identity.get("Manifest", {})
        components = []
        if isinstance(entries, dict):
            for name, metadata in sorted(entries.items()):
                item = {"name": name, "category": classify(str(name))}
                if isinstance(metadata, dict):
                    item["metadata"] = serialise(metadata)
                components.append(item)
        matches.append({
            "index": index,
            "match_reasons": reasons,
            "info": serialise(identity.get("Info", {})),
            "ap_chip_id": serialise(identity.get("ApChipID")),
            "ap_board_id": serialise(identity.get("ApBoardID")),
            "components": components,
        })

    device = profile["product_type"]
    supported = manifest_supports_product(manifest, device)
    return {
        "manifest": {
            "ProductVersion": manifest.get("ProductVersion"),
            "ProductBuildVersion": manifest.get("ProductBuildVersion"),
            "SupportedProductTypes": manifest.get("SupportedProductTypes"),
            "identity_count": len(identities),
        },
        "target": profile,
        "product_supported": supported,
        "matching_identities": matches,
        "result": "MANIFEST_HARDWARE_IDENTITY_FOUND" if supported and matches else "NO_VERIFIED_HARDWARE_IDENTITY",
        "authorization": "NOT_EVALUATED",
        "boot_compatibility": "NOT_EVALUATED",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--text", type=Path)
    args = parser.parse_args()

    report = build_report(load(args.manifest), load_profile(args.profile))
    payload = json.dumps(report, indent=2, sort_keys=True)
    print(payload)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(payload + "\n", encoding="utf-8")
    if args.text:
        args.text.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"Device: {report['target']['product_type']}",
            f"Board: {report['target']['board_config']}",
            f"Version: {report['manifest'].get('ProductVersion')}",
            f"Build: {report['manifest'].get('ProductBuildVersion')}",
            f"Product supported: {report['product_supported']}",
            f"Matching identities: {len(report['matching_identities'])}",
            f"Result: {report['result']}",
            "Authorization: NOT EVALUATED",
            "Boot compatibility: NOT EVALUATED",
        ]
        args.text.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return 0 if report["result"] == "MANIFEST_HARDWARE_IDENTITY_FOUND" else 1


if __name__ == "__main__":
    raise SystemExit(main())
