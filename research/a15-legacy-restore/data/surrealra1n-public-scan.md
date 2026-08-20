# surrealra1n public-source scan

Date: 2026-08-19

## Scope

Static review of the publicly accessible `development` branch of `pwnerblu/surrealra1n`. No exploit code was executed and no device was contacted.

## Findings

| Check | Finding | Classification |
|---|---|---|
| Publicly documented device scope | README describes A7/A8(X), A11, and A12/A13 iPhones | A13 reference |
| `iPhone12,8` references | Present in source search | A13/device-specific |
| `iPhone14,6` references | No repository search result | No documented SE 3 support found |
| `seprmvr64` references | Present in README/source | SEP-specific |
| Restore plumbing | `futurerestore` and restore-related source are present | Generic + platform-specific portions |
| Target conclusion | No evidence of an existing A15 implementation | A15 remains open |

## Evidence

The current `development` tree contains `surrealra1n.sh`, `futurerestore/`, `hax/`, `keys/`, and `manifest/`. The main script is approximately 181 KB and contains the device/restore orchestration. The project README explicitly describes the supported family as A7/A8(X), A11, and A12/A13 iPhones.

A repository search finds `iPhone12,8` in `surrealra1n.sh`, while a search for `iPhone14,6` returns no results. A search for `seprmvr64` finds references in the README and main script.

## Interpretation

The evidence supports using `surrealra1n` as an architectural reference for the SE 3 investigation, but does not reveal an existing A15 implementation to port. The missing capability is therefore still hardware/restore-chain research, not ordinary IPSW parsing.

## Next safe research step

Use the existing static scanner against a local clone of the `development` tree and generate a complete machine-readable inventory of all hardware identifiers, SEP references, restore components, and version-selection logic. This can then be compared with the `iPhone14,6`/19E241 manifest without executing the tool or modifying a device.
