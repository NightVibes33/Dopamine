# A15 Legacy Restore Research

Non-destructive research harness for the iPhone SE (3rd generation) legacy-restore question.

## Target

- Product: `iPhone14,6`
- Board: `D49AP`
- Platform: `t8110` / A15
- CPID / BDID: `0x8110` / `0x10`
- Project starting OS: iOS 26.4.2
- Target: iOS 15.4 / `19E241`

## Scope

The harness performs IPSW/BuildManifest metadata extraction, verified hardware-identity matching, component inventory, public-source comparison, and reproducible feasibility reporting. It does **not** bypass Apple's signing, modify boot-chain components, generate authorization tickets, exploit SecureROM/SEP, or perform a restore.

## Fast path

Analyze the verified Apple-hosted target without downloading the full 5.6 GiB IPSW:

```sh
./research/a15-legacy-restore/fetch-target.sh
```

The helper uses HTTP byte ranges to retrieve only `BuildManifest.plist` and writes:

```text
research/a15-legacy-restore/data/19E241/
├── BuildManifest.plist
├── validation.txt
├── report.json
├── report.txt
└── component-matrix.json
```

To analyze a locally downloaded IPSW instead:

```sh
./research/a15-legacy-restore/fetch-target.sh /path/to/iPhone14,6_15.4_19E241_Restore.ipsw
```

The local path is SHA-256 verified against `target-profile.json` first.

## Direct validator

```sh
python3 research/a15-legacy-restore/validate_manifest.py /path/to/BuildManifest.plist
```

Hardware matching uses the verified D49AP `DeviceClass` and CPID/BDID rather than assuming every BuildIdentity exposes `Info.ProductType`.

## Current feasibility result

See `FEASIBILITY.md` and `PUBLIC-BLOCKERS.md`. Current public evidence does not establish an A15 early-boot primitive equivalent to the A12/A13 `usbliter8` capability used by the reference downgrade work.
