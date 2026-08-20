# T8110 DFU-Associated Revision Hotspot

## Result

The current highest-ranked A15 SecureROM A0 → B0/B1 function-level revision hotspot is statically associated with the DFU subsystem.

### Evidence

- A15 A0 hotspot start: file offset `0xC2B8`.
- A15 B0/B1 paired hotspot start: file offset `0xC2B8`.
- Ibis maps the routine into executable `TEXT` in both ROM revisions.
- A0 routine size estimate: 27 decoded instructions.
- B0/B1 routine size estimate: 89 decoded instructions.
- Feature delta on the B0/B1 side: +62 decoded instructions, +8 conditional branches, +12 compares, +16 arithmetic operations, +4 loads, +4 stores, while direct calls fall from 4 to 1.
- Read-only PC-relative reference analysis resolves the printable CONST label `Apple Mobile Device (DFU Mode)` from the A0 routine.
- Broad static subsystem tag: `usb_dfu`.

The string reference establishes a **DFU association**, not an exact function name and not a vulnerability.

## Analysis provenance

String-label workflow run: `32405266381` — **success**.

Artifact: `9420023093`, digest `sha256:453ef9a9d64615611760ee2ad8909e0f9ab94cec334c66f01371e93259f1f20b`.

The artifact contains the string-reference report but not the SecureROM binaries; the binaries are deleted before upload.

## Interpretation

The same-start `0xC2B8` rewrite is now materially more interesting than an arbitrary revision delta because:

1. it lies in executable `TEXT`;
2. it is the strongest structural-change candidate in the A15 A0 → B0/B1 comparison;
3. it is associated with the immutable DFU path through a resolved read-only string reference;
4. the production-step version contains substantially more internal branch/compare/arithmetic logic than the early A0 version.

Possible explanations include normal stepping support, refactoring/inlining, diagnostics changes, or defensive hardening. Static evidence alone cannot distinguish those explanations.

## Secondary labeled hotspot

A lower-ranked changed routine around A0 `0xE530` → B0/B1 `0xE7C8` references labels including `pmap-io-ranges`, `l2-tt-%d`, and `pt-region-%d`, which is consistent with platform/page-table configuration work. This is useful context because public research already indicates that A14+ changed early DMA/DART handling relative to A12/A13.

## Next research discriminator

Trace the descriptor-bearing DFU routine across the production A14 B1 ROM and the two A15 revisions. If the A15 B0/B1 structure is inherited directly from A14 or differs only by broad architecture changes, the hotspot is less likely to represent A15-specific hardening. If the A15 A0 form is unique and B0/B1 introduces a distinct rewrite within the same SoC generation, it remains a higher-value manual static-review candidate.

This document records static evidence only; no exploitability conclusion is made.
