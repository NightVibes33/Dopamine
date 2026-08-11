
#!/usr/bin/env python3
"""Summarize arithmetic-width changes without generating trigger inputs."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


X_REGISTER = re.compile(r"(?<![A-Za-z0-9_])(?:x(?:[12]?\d|3[01])|xzr)(?![A-Za-z0-9_])")
W_REGISTER = re.compile(r"(?<![A-Za-z0-9_])(?:w(?:[12]?\d|3[01])|wzr)(?![A-Za-z0-9_])")


def width_counts(rows):
    counts = {"x64": 0, "w32": 0, "mixed": 0, "neither": 0}
    for row in rows:
        operands = row["operands"]
        has_x = bool(X_REGISTER.search(operands))
        has_w = bool(W_REGISTER.search(operands))
        if has_x and has_w:
            counts["mixed"] += 1
        elif has_x:
            counts["x64"] += 1
        elif has_w:
            counts["w32"] += 1
        else:
            counts["neither"] += 1
    return counts


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: ave_lfs_width_delta.py <evidence.json> <report.md>")
    evidence = json.loads(Path(sys.argv[1]).read_text())
    streams = evidence["streams"]
    names = (
        "beta3_host_lfs_calculator",
        "beta4_host_lfs_calculator",
        "beta3_fw_lfs_write_dma",
        "beta4_fw_lfs_write_dma",
    )
    counts = {name: width_counts(streams[name]["arithmetic"]) for name in names}

    b3 = counts["beta3_host_lfs_calculator"]
    b4 = counts["beta4_host_lfs_calculator"]
    if b3["w32"] <= b3["x64"]:
        raise SystemExit("beta3 host arithmetic is not predominantly 32-bit")
    if b4["x64"] <= b4["w32"]:
        raise SystemExit("beta4 host arithmetic is not predominantly 64-bit")

    lines = [
        "# AppleAVE2 LFS arithmetic-width delta",
        "",
        "Static/offline validation only. No dimensions or driver requests are generated.",
        "",
        "| Stream | 64-bit-only ops | 32-bit-only ops | Mixed-width ops | Other |",
        "|---|---:|---:|---:|---:|",
    ]
    for name in names:
        row = counts[name]
        lines.append(
            f"| `{name}` | {row['x64']} | {row['w32']} | "
            f"{row['mixed']} | {row['neither']} |"
        )
    lines += [
        "",
        "## Validation assessment",
        "",
        "Beta 3 performs the host calculator's arithmetic predominantly in 32-bit registers; beta 4 performs it predominantly in 64-bit registers. This is direct binary evidence of arithmetic-width hardening in the allocation-side calculator.",
        "",
        "The firmware write-DMA streams retain the same instruction, arithmetic, and memory-operation counts in the source evidence. That supports continued investigation of a host-allocation versus firmware-consumer width mismatch on beta 3.",
        "",
        "This delta does not by itself prove an integer overflow, an undersized allocation, out-of-bounds DMA, memory corruption, reachability from the blocked user client, or a kernel primitive.",
    ]
    Path(sys.argv[2]).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
