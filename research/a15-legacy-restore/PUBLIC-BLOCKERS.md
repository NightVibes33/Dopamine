# Public blocker assessment — A15 / iPhone14,6

## Reference technique

The current public `surrealra1n` development branch describes tethered downgrade support for A7/A8(X), A11, and A12/A13 iPhones. Its recent A12/A13 work is based on the `usbliter8` SecureROM research path.

## A15 comparison

Public `usbliter8` device/support information reviewed for this project enumerates A12/A13 targets, including iPhone SE (2nd generation, A13), but not iPhone SE (3rd generation, A15). Independent writeups likewise describe the underlying SecureROM/USB exploit class as A12/A13.

Separate public A15 TXM/SPTM patch-analysis exists and includes iPhone SE 3 references. This is a downstream patch-analysis capability, not evidence of an A15 SecureROM/DFU entry primitive. It therefore cannot substitute for the missing earliest-stage boot control required to transfer the A12/A13 downgrade architecture.

## Real 19E241 firmware result

The project has now parsed the actual Apple `BuildManifest.plist` through GitHub Actions run `32402473440`.

Confirmed:

- `iPhone14,6` is listed as a supported product.
- Two D49AP identities match CPID `0x8110` and BDID `0x10`.
- Each identity has 80 components.
- iBSS, iBEC, iBoot, LLB, SEP, RestoreSEP, DeviceTree, kernel, baseband and restore environment entries are present.
- The erase/update identities share the same boot-chain/SEP/kernel paths and differ at path level only in `RestoreRamDisk` and its `RestoreTrustCache`.

The firmware-selection question is therefore solved.

## Consequence for this project

The unresolved dependency is upstream of `futurerestore`, BuildManifest parsing, and component selection:

1. An A15 early-boot capability sufficient to control the restore/boot path.
2. Independent evidence for the relevant A15 SEP/firmware compatibility.
3. A valid restore-authorization strategy for the target state.

No public capability satisfying item 1 was identified in the reviewed sources as of 2026-08-20.

## Current disposition

**BLOCKED — missing public A15 early-boot primitive.**

This disposition should be revisited if new A15 SecureROM, DFU, or equivalent early-boot research becomes public.
