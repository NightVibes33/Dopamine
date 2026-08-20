# A15 Early-Boot Primitive Requirements

Target: `iPhone14,6` / D49AP / A15 (`t8110`, CPID `0x8110`, BDID `0x10`)

Purpose: define the **capability contract** that any future public A15 research would need to satisfy before it could materially change this project's downgrade feasibility assessment. This document intentionally does not describe exploit construction or execution.

## Required capability classes

| Requirement | Why it is needed | Evidence threshold | Current status |
|---|---|---|---|
| Retail D49AP applicability | Prototype-only behavior is insufficient for the SE 3 target | Reproducible evidence on retail `iPhone14,6`/D49AP hardware | NOT ESTABLISHED |
| Early-boot control | The reference A12/A13 architecture depends on control before the normal signed restore chain takes over | Public research demonstrating equivalent control on A15/t8110 | NOT ESTABLISHED |
| Deterministic recovery | Research must return the device to a known state after failure/reboot | Publicly documented, repeatable recovery behavior | NOT ESTABLISHED |
| Component-hand-off visibility | Required to reason about iBSS/iBEC/iBoot/restore transitions | Evidence describing the stage reached and observable state | NOT ESTABLISHED |
| Target-build relevance | Generic A15 research must be relevant to D49AP and the `19E241` component set | Hardware/build mapping or equivalent technical evidence | NOT ESTABLISHED |
| SEP-safe boundary | Early-boot control alone must not be mistaken for SEP compatibility | Independent SEP compatibility evidence | NOT ESTABLISHED |

## Evidence that does **not** satisfy the contract by itself

- A12/A13 `usbliter8` or `surrealra1n` support.
- checkm8-class support, which does not extend to A15.
- TXM/SPTM patch-analysis performed after the missing early-boot stage.
- A15 tooling demonstrated only on Apple prototype/JTAG-capable hardware.
- Presence of A15 firmware components in an IPSW or BuildManifest.
- A kernel exploit, sandbox escape, or userspace privilege escalation that starts after the relevant restore/boot authorization boundary.

## Prototype/JTAG research note

Public A15 tooling such as `Anya` demonstrates that CPID `0x8110` firmware/security research exists on JTAG-capable Apple prototype hardware. That is useful architectural evidence, but it does **not** establish a retail SE 3 SecureROM/DFU primitive and therefore does not satisfy the first two requirements above.

## Decision rule

A newly published technique changes this project's status only if it supplies evidence for **retail D49AP applicability + sufficiently early boot control**. Once those two gates are met, the project can move immediately to the already-prepared `19E241` component/SEP compatibility phase.

## Current result

**BLOCKED AT EARLY BOOT.**

The firmware-selection and BuildManifest work is complete; the missing capability is upstream of restore-engine adaptation.
