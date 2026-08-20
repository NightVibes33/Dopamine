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
| E-009 | Public `usbliter8` research supports SE 2/A13 but not SE 3/A15 | Public device/support lists | CONFIRMED |
| E-010 | A15 SEP compatibility with the proposed legacy environment is established | Independent technical evidence | NOT ESTABLISHED |
| E-011 | An A15 early-boot/SecureROM primitive equivalent to the A12/A13 path is established | Independent technical evidence | NOT ESTABLISHED |
| E-012 | A restore-authorization bypass for this A15 target is established | Security-sensitive capability | NOT ESTABLISHED |

## Real-manifest run

GitHub Actions run `32402243047` completed successfully. It range-fetched the Apple-hosted IPSW ZIP metadata and `BuildManifest.plist`, ran the unit tests, verified the hardware identities, generated the structured report and component matrix, and uploaded artifact `9418906495` (`iPhone14-6-19E241-manifest-analysis`).

## Decision rule

Only `CONFIRMED` claims should be treated as established facts. `NOT FOUND` and `NOT ESTABLISHED` are research gaps rather than proof of theoretical impossibility.

## Current assessment

The BuildManifest question is resolved: `19E241` is unquestionably packaged for `iPhone14,6` / D49AP and includes the expected production DFU, boot-chain, SEP, kernel, baseband, and restore environment components. The decisive remaining blocker is no longer firmware identification. It is the absence of a publicly established A15 early-boot capability equivalent to the A12/A13 `usbliter8` path, followed by unresolved SEP/restore compatibility.
