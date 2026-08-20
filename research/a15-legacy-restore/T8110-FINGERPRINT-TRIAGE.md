# T8110 SecureROM Function-Diff Triage

This note records the first real static A15 SecureROM A0 → B0/B1 comparison and the quality controls applied before treating any delta as meaningful. It is static reverse-engineering triage only; no exploit construction or device execution is performed.

## First real comparison

Input revisions are pinned by hash in `rom-sources.json` and fetched only for CI analysis. ROM binaries are removed before artifact upload.

Observed aggregate results from the first completed comparison:

- ROM size: 1 MiB per revision.
- Same-position 4 KiB chunk similarity: ~80.47%.
- Changed aligned 4-byte words: 35,030.
- Heuristic A0 function candidates: 956.
- Heuristic B0/B1 function candidates: 962.
- Exact mnemonic-fingerprint matches before boundary de-duplication: 932.
- The majority of candidate functions therefore remain structurally stable across revisions.

## Quality issue discovered

The first fingerprint output contained multiple heuristic starts only a few instructions apart that terminated at the same return address. These are likely overlapping prologue detections rather than distinct functions.

`function-fingerprint-diff.py` now collapses near-identical same-end boundaries, merges their discovery evidence, and prefers direct-BL-backed/wider boundaries. The revised result must be used for candidate counts and unmatched-function triage.

## Interpretation rules

A changed region is **not** a vulnerability merely because it differs between ROM revisions. Revision deltas can reflect:

- hardware stepping support;
- compiler/layout differences;
- diagnostic or production configuration;
- new peripherals or initialization paths;
- hardening;
- bug fixes;
- unrelated refactoring.

A region is promoted for manual static review only when multiple independent signals agree, for example:

1. a stable function correspondence can be established;
2. the function materially changed rather than merely relocated;
3. surrounding static evidence associates it with an early-boot subsystem of interest;
4. the behavior is relevant to retail T8110/D49AP rather than prototype-only paths;
5. the finding survives comparison across available T8110 revisions.

## Current research direction

After the boundary-de-duplicated CI result is available, the next analysis product is a subsystem-level delta map. Its purpose is to distinguish routine stepping changes from security-relevant parser/state-machine/memory-management changes without claiming exploitability.

No SecureROM vulnerability has been established by the current diff results.
