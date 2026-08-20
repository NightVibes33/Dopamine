#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROFILE_PATH = Path(__file__).with_name("target-profile.json")


def load_profile(path: Path | None = None) -> dict[str, Any]:
    return json.loads((path or PROFILE_PATH).read_text(encoding="utf-8"))


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return int.from_bytes(value, "big")
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def manifest_supports_product(manifest: dict[str, Any], product_type: str) -> bool:
    supported = manifest.get("SupportedProductTypes")
    if isinstance(supported, list) and product_type in supported:
        return True
    value = manifest.get("ProductType")
    if isinstance(value, str) and value == product_type:
        return True
    return False


def identity_matches(identity: dict[str, Any], profile: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    info = identity.get("Info") if isinstance(identity.get("Info"), dict) else {}

    product = info.get("ProductType")
    if product == profile["product_type"]:
        reasons.append("Info.ProductType")

    device_class = info.get("DeviceClass")
    if isinstance(device_class, str) and device_class.lower() == str(profile["board_config"]).lower():
        reasons.append("Info.DeviceClass")

    chip = _int(identity.get("ApChipID"))
    board = _int(identity.get("ApBoardID"))
    if chip == int(profile["cpid"]) and board == int(profile["bdid"]):
        reasons.append("ApChipID+ApBoardID")

    return bool(reasons), reasons


def matching_identities(manifest: dict[str, Any], profile: dict[str, Any]) -> list[tuple[int, dict[str, Any], list[str]]]:
    identities = manifest.get("BuildIdentities", [])
    if not isinstance(identities, list):
        return []
    matches = []
    for index, identity in enumerate(identities):
        if not isinstance(identity, dict):
            continue
        ok, reasons = identity_matches(identity, profile)
        if ok:
            matches.append((index, identity, reasons))
    return matches
