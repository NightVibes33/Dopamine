# A15 Legacy-Restore Evidence Register

This register separates observations from conclusions so an unverified assumption does not become a compatibility claim.

| ID | Claim | Evidence class | Status |
|---|---|---|---|
| E-001 | `iPhone14,6` is the SE 3 product identifier | Public device metadata | CONFIRMED |
| E-002 | `19E241` is iOS 15.4 | Public IPSW/build metadata | CONFIRMED |
| E-003 | `19E241` supports product `iPhone14,6` | Actual Apple `BuildManifest.plist` | CONFIRMED |
| E-004 | The manifest contains D49AP / CPID `0x8110` / BDID `0x10` identities | Actual Apple `BuildManifest.plist` | CONFIRMED |
| E-005 | The manifest contains both erase and update IPSW identities | Actual Apple `BuildManifest.plist` | CONFIRMED |
| E-006 | Each matching identity contains 80 restore components | Actual Apple `BuildManifest.plist` | CONFIRMED |
| E-007 | A13 `surrealra1n` support exists | Public project documentation/source | CONFIRMED |
| E-008 | `surrealra1n` documents A15 support | Public project documentation/source | NOT FOUND |
| E-009 | Public `usbliter8` SecureROM research targets A12/A13, including SE 2/A13, not SE 3/A15 | Public device/support lists and independent writeups | CONFIRMED |
| E-010 | Public A15 TXM/SPTM patch-analysis exists, including SE 3 references | Public research source | CONFIRMED |
| E-011 | That A15 TXM/SPTM work supplies an A15 SecureROM/DFU primitive | Public research source | NOT ESTABLISHED |
| E-012 | A15 SEP compatibility with the proposed legacy environment is established | Independent technical evidence | NOT ESTABLISHED |
| E-013 | A restore-authorization bypass for this A15 target is established | Security-sensitive capability | NOT ESTABLISHED |

## Verified real-manifest run

GitHub Actions run `32402473440` completed successfully. It range-fetched the Apple-hosted IPSW ZIP metadata and `BuildManifest.plist`, ran syntax checks and unit tests, verified both D49AP hardware identities, generated the structured report and component matrix, and uploaded artifact `9418990839` (`iPhone14-6-19E241-manifest-analysis`).

Artifact digest:

`sha256:941ca6f70e6e376eab34eb2a5df0143ea1d8f43a681ce054f4aa7444c4c12a88`

The generated manifest summary is committed at `data/19E241/manifest-summary.json`.

## Decision rule

Only `CONFIRMED` claims should be treated as established facts. `NOT FOUND` and `NOT ESTABLISHED` are research gaps rather than proof of theoretical impossibility.

## Current assessment

The BuildManifest question is resolved: `19E241` is unquestionably packaged for `iPhone14,6` / D49AP and includes the expected production DFU, boot-chain, SEP, kernel, baseband, and restore-environment components.

The public A15 TXM/SPTM patch-analysis result does not change the decisive blocker because that work assumes some earlier mechanism for reaching/controlling the relevant boot stage; it is not evidence of an A15 SecureROM/DFU entry primitive. The unresolved dependency therefore remains an A15 early-boot capability equivalent in role to the A12/A13 `usbliter8` path, followed by SEP/restore compatibility evidence.
