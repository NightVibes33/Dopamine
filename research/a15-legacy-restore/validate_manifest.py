#!/usr/bin/env python3
"""Offline BuildManifest inspector for A15 legacy-restore research.

This tool only parses a local plist. It performs no device communication,
restore authorization, signing bypass, or boot-chain modification.
"""

from __future__ import annotations

import argparse
import plistlib
import sys
from pathlib import Path
from typing import Any


def load_plist(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        obj = plistlib.load(f)
    if not isinstance(obj, dict):
        raise ValueError("BuildManifest.plist root is not a dictionary")
    return obj


def device_matches(value: Any, device: str) -> bool:
    if isinstance(value, str):
        return value == device
    if isinstance(value, list):
        return device in value
    return False


def walk(node: Any, path: str = ""):
    if isinstance(node, dict):
        for key, value in node.items():
            current = f"{path}/{key}" if path else str(key)
            yield current, value
            yield from walk(value, current)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, f"{path}[{index}]")


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect an IPSW BuildManifest offline")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--device", default="iPhone14,6")
    args = parser.parse_args()

    try:
        manifest = load_plist(args.manifest)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 2

    print(f"Manifest: {args.manifest}")
    print(f"Device:   {args.device}")

    identity_keys = ["ProductBuildVersion", "ProductVersion", "ProductType"]
    for key in identity_keys:
        if key in manifest:
            print(f"{key}: {manifest[key]}")

    identities = manifest.get("BuildIdentities", [])
    if not isinstance(identities, list):
        print("ERROR: BuildIdentities is not a list")
        return 2

    matches = []
    for index, identity in enumerate(identities):
        if not isinstance(identity, dict):
            continue
        info = identity.get("Info", {})
        if not isinstance(info, dict):
            info = {}
        product_type = info.get("DeviceClass") or info.get("ProductType")
        compatible = device_matches(info.get("ProductType"), args.device)
        if not compatible:
            compatible = device_matches(identity.get("ApBoardID"), args.device)
        # BuildManifest variants commonly identify devices through Info/ProductType.
        if info.get("ProductType") == args.device:
            compatible = True
        if compatible:
            matches.append((index, identity))

    print(f"Build identities: {len(identities)}")
    print(f"Direct device matches: {len(matches)}")

    # Print component inventory without extracting or modifying payloads.
    for index, identity in matches:
        manifest_entries = identity.get("Manifest", {})
        if not isinstance(manifest_entries, dict):
            continue
        print(f"\nIdentity #{index} components ({len(manifest_entries)}):")
        for component, metadata in sorted(manifest_entries.items()):
            if isinstance(metadata, dict):
                digest = metadata.get("Digest")
                size = metadata.get("Info", {}).get("Size") if isinstance(metadata.get("Info"), dict) else None
                bits = []
                if digest:
                    bits.append(f"digest={digest.hex() if isinstance(digest, bytes) else digest}")
                if size is not None:
                    bits.append(f"size={size}")
                print(f"  - {component}: {', '.join(bits) or 'metadata present'}")
            else:
                print(f"  - {component}")

    if not matches:
        print("\nRESULT: NO_DIRECT_DEVICE_IDENTITY")
        print("The target manifest does not expose an identity directly matching the requested product type.")
        return 1

    print("\nRESULT: MANIFEST_IDENTITY_FOUND")
    print("This is an offline manifest result only; it does not establish restore authorization or boot compatibility.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
