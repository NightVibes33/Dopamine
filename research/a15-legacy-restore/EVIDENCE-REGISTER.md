# A15 Legacy-Restore Evidence Register

This register separates observations from conclusions so the project does not accidentally turn an unverified assumption into a compatibility claim.

| ID | Claim | Evidence class | Status |
|---|---|---|---|
| E-001 | `iPhone14,6` is the SE 3 product identifier | Public device metadata | CONFIRMED |
| E-002 | `19E241` is iOS 15.4 | Public IPSW/build metadata | CONFIRMED |
| E-003 | `19E241` contains an `iPhone14,6` build identity | Requires actual BuildManifest parse | PENDING |
| E-004 | A13 `surrealra1n` support exists | Public project documentation/source | CONFIRMED |
| E-005 | `surrealra1n` documents A15 support | Public project documentation/source | NOT FOUND |
| E-006 | A15 SEP compatibility with the proposed legacy environment is established | Independent technical evidence | NOT ESTABLISHED |
| E-007 | A15 boot-chain compatibility with the proposed legacy environment is established | Independent technical evidence | NOT ESTABLISHED |
| E-008 | A restore-authorization bypass is available | Security-sensitive capability | NOT ESTABLISHED |

## Decision rule

Only claims marked `CONFIRMED` should be treated as established facts. `PENDING`, `NOT FOUND`, and `NOT ESTABLISHED` are research gaps, not negative proof.

## Current assessment

The project has enough evidence to continue static firmware analysis, but not enough evidence to claim that an SE 3 can be downgraded from iOS 26.4.2 to iOS 15.4. The decisive missing evidence remains the target BuildManifest data plus independent A15 SEP/boot-chain compatibility evidence.
