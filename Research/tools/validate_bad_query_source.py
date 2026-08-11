#!/usr/bin/env python3
"""Validate the public bad_query source chain without compiling or executing it."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

REQUIRED = [
    "container_query_create",
    "container_query_set_class",
    "container_query_set_group_identifiers",
    "container_query_operation_set_part",
    "container_query_operation_set_part_domain",
    "container_query_get_single_result",
    "container_copy_sandbox_token",
    "sandbox_extension_consume",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    data = args.source.read_bytes()
    text = data.decode("utf-8", errors="replace")
    hits = {name: text.count(name) for name in REQUIRED}
    traversal = "../../../../../../../..%s" in text
    complete = all(count > 0 for count in hits.values()) and traversal
    report = {
        "schema": 1,
        "candidate": "bad_query",
        "upstream_commit": "73ef6da",
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "required_api_hits": hits,
        "traversal_template_present": traversal,
        "static_chain_complete": complete,
        "target": {"device": "iPhone17,3", "build": "24A5380h"},
        "disposition": "public-poc-applicable-unverified-on-device" if complete else "source-chain-incomplete",
        "cve_identity": None,
        "safety": {"compiled": False, "executed": False, "live_device_test": False},
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if not complete:
        raise SystemExit("public source does not contain the expected chain")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
