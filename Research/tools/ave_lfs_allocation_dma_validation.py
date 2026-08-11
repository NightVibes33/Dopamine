#!/usr/bin/env python3
"""Machine-check the LFSOutput allocation-to-DMA evidence chain.

Static analysis only. This validator does not derive dimensions, open IOKit,
invoke selectors, or interact with a device.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import ave_lfsoutput_dma_candidate as candidate
from ave_lfs_width_delta import width_counts


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    if len(sys.argv) != 8:
        raise SystemExit(
            "usage: ave_lfs_allocation_dma_validation.py <b3-kext> <b4-kext> "
            "<b3-fw> <b4-fw> <evidence.json> <report.md> <result.json>"
        )

    k3, k4, fw3, fw4, evidence_path, report_path, result_path = sys.argv[1:]
    chain = candidate.analyze(k3, k4, fw3, fw4)
    evidence = json.loads(Path(evidence_path).read_text())
    streams = evidence["streams"]

    b3_width = width_counts(streams["beta3_host_lfs_calculator"]["arithmetic"])
    b4_width = width_counts(streams["beta4_host_lfs_calculator"]["arithmetic"])
    fw3_width = width_counts(streams["beta3_fw_lfs_write_dma"]["arithmetic"])
    fw4_width = width_counts(streams["beta4_fw_lfs_write_dma"]["arithmetic"])

    check({row[3] for row in chain["result_stores3"]} == {0x37C},
          "beta3 calculator result does not land exclusively in +0x37c")
    check(chain["alloc3"][2] and chain["alloc3"][3] and chain["alloc3"][5],
          "beta3 allocation source-to-sink tuple incomplete")
    check(chain["helper3"][0] and chain["helper3"][1],
          "beta3 descriptor address/size export incomplete")
    check(chain["fw3"]["address_load"], "beta3 firmware destination-address load absent")
    check(chain["fw3"]["madd_count"] >= 2, "beta3 firmware geometry arithmetic absent")
    check(b3_width["w32"] > b3_width["x64"],
          "beta3 allocation calculator is not predominantly 32-bit")
    check(b4_width["x64"] > b4_width["w32"],
          "beta4 allocation calculator is not predominantly 64-bit")
    check(fw3_width == fw4_width,
          "firmware arithmetic-width profile changed across builds")

    result = {
        "candidate_id": "IOS27-AVE-003-LFS",
        "target": "iPhone17,3 / 24A5380h",
        "method": "exact-binary static source/control/sink validation",
        "scope": "offline; no trigger dimensions; no device interaction",
        "source": {
            "calculator": f"0x{chain['calc3']:x}",
            "result_slot": "descriptor +0x37c",
            "arithmetic_width": b3_width,
        },
        "allocation_sink": {
            "function": f"0x{chain['alloc3'][1]:x}",
            "size_load": f"0x{chain['alloc3'][2]:x}",
            "size_to_x4": f"0x{chain['alloc3'][3]:x}",
            "callee": f"0x{chain['alloc3'][5]:x}",
        },
        "firmware_sink": {
            "symbol": chain["fw3"]["symbol"],
            "function": f"0x{chain['fw3']['start']:x}",
            "destination_address_load": f"0x{chain['fw3']['address_load']:x}",
            "serialized_backing_size_loaded": False,
            "geometry_madd_count": chain["fw3"]["madd_count"],
            "arithmetic_width": fw3_width,
        },
        "counterevidence": [
            "No concrete accepted input is generated or tested.",
            "A pre-allocation domain clamp may still make the 32-bit result safe.",
            "The exact maximum DMA end offset has not been symbolically bounded against the allocation.",
            "Runtime reachability remains blocked at AppleAVE2 user-client initialization.",
        ],
        "disposition": "deferred",
        "survives": "uncertain",
        "proof_gap": (
            "Prove or falsify, over the accepted input domain, that the beta3 "
            "allocation size is always at least the maximum firmware DMA end offset."
        ),
    }
    Path(result_path).write_text(json.dumps(result, indent=2) + "\n")

    lines = [
        "# AppleAVE2 LFSOutput allocation-to-DMA validation",
        "",
        "Candidate: `IOS27-AVE-003-LFS`",
        "",
        "Method: exact-binary static source/control/sink tracing. No trigger values or device requests are generated.",
        "",
        "## Rubric",
        "",
        "- [x] Exact beta-3 allocation-size producer and result slot identified.",
        "- [x] Exact beta-3 surface-allocation sink and size argument identified.",
        "- [x] Kernel-to-firmware descriptor identity linked through address/size export.",
        "- [x] H17 destination-address and geometry-derived DMA consumer identified.",
        "- [ ] Accepted-domain inequality between allocation size and maximum DMA end offset proven.",
        "",
        "## Evidence",
        "",
        f"- Beta-3 calculator `0x{chain['calc3']:x}` returns through descriptor `+0x37c`.",
        f"- Allocation function `0x{chain['alloc3'][1]:x}` loads that slot at `0x{chain['alloc3'][2]:x}`, moves it to `x4` at `0x{chain['alloc3'][3]:x}`, and calls `0x{chain['alloc3'][5]:x}`.",
        "- The descriptor helper exports both mapped address and actual backing size.",
        f"- H17 `{chain['fw3']['symbol']}` loads the destination address but not the adjacent backing-size field, and contains {chain['fw3']['madd_count']} geometry-derived multiply-add operations.",
        f"- Beta 3 host width counts: {b3_width}; beta 4: {b4_width}. Firmware width profile is unchanged: {fw3_width}.",
        "",
        "## Disposition",
        "",
        "**Deferred; candidate survives as uncertain.** The complete mismatch-shaped source-to-sink chain is now machine checked, but memory corruption is not established. A caller-side accepted-domain clamp could still ensure the beta-3 32-bit allocation is large enough.",
        "",
        "Remaining proof gap: symbolically prove or falsify that the beta-3 allocation size is always at least the maximum H17 DMA end offset over every accepted input, without emitting a concrete triggering dimension pair.",
    ]
    Path(report_path).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
