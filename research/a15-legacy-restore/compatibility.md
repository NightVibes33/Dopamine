# A13 → A15 Legacy-Restore Compatibility Matrix

## Scope

This document records publicly observable, non-destructive compatibility facts for legacy-restore research. It does not document exploit primitives, signing bypasses, or instructions for defeating device security.

| Property | iPhone SE (2nd gen) | iPhone SE (3rd gen) |
|---|---|---|
| Product identifier | iPhone12,8 | iPhone14,6 |
| SoC | A13 Bionic | A15 Bionic |
| Architecture | arm64e | arm64e |
| `surrealra1n` publicly documented support | A12/A13 research support | No documented A15 support |
| Checkm8-class BootROM support | No | No |
| Target used in this project | Reference platform | Target platform |

## What transfers conceptually

- IPSW/BuildManifest parsing is hardware-independent and can be reused.
- Restore-component inventory and version comparison can be automated.
- Device/build compatibility can be evaluated without touching a device.

## What cannot be assumed

- An A13 restore technique automatically works on A15.
- A working A13 SEP/restore path is compatible with an A15 SEP.
- An unsigned IPSW can be restored merely because its files and hashes are valid.
- A successful tethered A13 downgrade establishes A15 feasibility.

## Required evidence before claiming A15 feasibility

1. A publicly documented A15 primitive providing the control required by the proposed restore architecture.
2. A demonstrated compatibility relationship between the target OS components and the A15 firmware/SEP environment.
3. A reproducible, non-destructive validation result showing the proposed component set is internally consistent for `iPhone14,6`.

## Current conclusion

For `iPhone14,6` → iOS 15.4 (`19E241`) from a modern iOS release, public A13 downgrade work is useful as an architectural reference but does not establish an A15 downgrade path. The branch therefore treats A15 support as an open research question rather than claiming that the existing A13 method can be ported directly.
