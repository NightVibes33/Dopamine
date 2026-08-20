#!/usr/bin/env python3
"""Offline BuildManifest inspector for A15 legacy-restore research."""
from __future__ import annotations

import argparse
import plistlib
import sys
from pathlib import Path
from typing import Any

from manifest_utils import load_profile, manifest_supports_product, matching_identities


def load_plist(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        obj = plistlib.load(f)
    if not isinstance(obj, dict):
        raise ValueError("BuildManifest.plist root is not a dictionary")
    return obj


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect an IPSW BuildManifest offline")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--profile", type=Path)
    args = parser.parse_args()

    try:
        manifest = load_plist(args.manifest)
        profile = load_profile(args.profile)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 2

    device = profile["product_type"]
    print(f"Manifest: {args.manifest}")
    print(f"Target:   {device} / {profile['board_config']} / CPID {profile['cpid_hex']} / BDID {profile['bdid_hex']}")
    print(f"Version:  {manifest.get('ProductVersion')}")
    print(f"Build:    {manifest.get('ProductBuildVersion')}")
    print(f"Product supported: {manifest_supports_product(manifest, device)}")

    identities = manifest.get("BuildIdentities", [])
    if not isinstance(identities, list):
        print("ERROR: BuildIdentities is not a list")
        return 2

    matches = matching_identities(manifest, profile)
    print(f"Build identities: {len(identities)}")
    print(f"Hardware identity matches: {len(matches)}")

    for index, identity, reasons in matches:
        entries = identity.get("Manifest", {})
        if not isinstance(entries, dict):
            continue
        print(f"\nIdentity #{index} matched via {', '.join(reasons)}; components={len(entries)}")
        for component, metadata in sorted(entries.items()):
            bits: list[str] = []
            if isinstance(metadata, dict):
                info = metadata.get("Info") if isinstance(metadata.get("Info"), dict) else {}
                path = info.get("Path")
                digest = metadata.get("Digest") or info.get("Digest")
                if path:
                    bits.append(f"path={path}")
                if digest:
                    bits.append(f"digest={digest.hex() if isinstance(digest, bytes) else digest}")
            print(f"  - {component}: {', '.join(bits) or 'metadata present'}")

    if not manifest_supports_product(manifest, device):
        print("\nRESULT: PRODUCT_NOT_SUPPORTED_BY_MANIFEST")
        return 1
    if not matches:
        print("\nRESULT: PRODUCT_SUPPORTED_BUT_NO_HARDWARE_IDENTITY_MATCH")
        print("The product is listed by the manifest, but no identity matched the verified board/CPID/BDID profile.")
        return 1

    print("\nRESULT: MANIFEST_HARDWARE_IDENTITY_FOUND")
    print("This proves only manifest targeting; restore authorization and boot compatibility are not evaluated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
