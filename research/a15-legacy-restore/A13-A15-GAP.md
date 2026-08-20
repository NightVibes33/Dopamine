# A13 → A15 Gap Report

## Scope

Static research comparison of the publicly documented `surrealra1n` support boundary against the `iPhone14,6` A15 target. This report does not implement or describe an exploit, signing bypass, SEP compromise, or device-security bypass.

| Subsystem | A13/reference evidence | A15 target | Gap | Status |
|---|---|---|---|---|
| IPSW/BuildManifest parsing | Generic restore metadata | Same format family | None at tooling level | REUSABLE |
| Product/device selection | A12/A13 identifiers documented in project | `iPhone14,6` | No documented A15 path | GAP |
| Restore plumbing | Project has restore-tool integration | A15 restore path unknown | Hardware-specific assumptions must be identified | OPEN |
| Boot components | A12/A13-era component handling | A15/D49 components | Different generation | OPEN |
| SEP | `seprmvr64` appears in public project | A15 SEP behavior differs | No documented equivalent | BLOCKER |
| Boot authorization | Existing A12/A13 research context | A15 authorization state | No public A15 support established | BLOCKER |
| Checkm8-class primitive | Not applicable to A12/A13 | Not applicable to A15 | Cannot transfer a checkm8 assumption | BLOCKER |
| A15 implementation | None in scanned source | Required | No implementation identified | MISSING |

## What we can reuse

- IPSW parsing and manifest inspection.
- Component inventory and metadata reporting.
- Device/build metadata handling.
- Static source analysis and compatibility documentation.

## What remains unresolved

1. A publicly documented A15 capability sufficient for the proposed restore architecture.
2. Evidence that the target iOS 15.4 SEP/firmware set can operate with the relevant A15 restore environment.
3. Evidence that the boot chain can accept the resulting component set.
4. A reproducible end-to-end validation method that does not rely on fabricated signatures or unsupported assumptions.

## Conclusion

The A13 implementation is useful as a reference for identifying architecture boundaries, but the scan does not reveal an A15 implementation that can simply be enabled. The current evidence therefore supports **research tooling and compatibility analysis**, not a demonstrated A15 downgrade.

The next safe technical milestone is to populate the component-level matrix from the actual `19E241` BuildManifest and compare those versions against publicly documented A15 firmware data.
