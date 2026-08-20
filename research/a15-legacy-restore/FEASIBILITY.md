# A15 Legacy-Restore Feasibility

## Current target

- Device: `iPhone14,6` (iPhone SE 3rd generation)
- SoC: A15
- Target: iOS 15.4
- Build: `19E241`
- Current device OS: iOS 26.4.2 (project target)

## Evaluation stages

| Stage | Status | Meaning |
|---|---|---|
| IPSW/manifest parsing | IMPLEMENTED | Offline tooling exists |
| Device identity matching | IMPLEMENTED | `iPhone14,6` can be checked against the manifest |
| Component inventory | IMPLEMENTED | Restore components can be enumerated |
| Component-version compatibility | OPEN | Requires actual target manifest data |
| Restore authorization | NOT EVALUATED | Outside the offline analyzer |
| SEP compatibility | OPEN | Requires platform-specific evidence |
| Boot compatibility | OPEN | Requires platform-specific evidence |
| A15 legacy-restore capability | OPEN | No conclusion from manifest parsing alone |

## Interpretation

A valid BuildManifest proves that an IPSW contains an identity for a product. It does **not** prove that Apple will authorize the restore, that its SEP/firmware combination is compatible with the current device state, or that the resulting system can boot.

The SE 2/A13 downgrade work is treated as a reference implementation, not evidence that the same mechanism works on A15.

## Current conclusion

`iPhone14,6` → `19E241` remains **unproven**. The next evidence required is a concrete component and firmware compatibility report for the target IPSW followed by comparison with publicly documented A15 restore-chain research.

No device modification should occur until those checks establish a viable path.
