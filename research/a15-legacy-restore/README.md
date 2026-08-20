# A15 Legacy Restore Research

This branch is a non-destructive research harness for studying legacy IPSW compatibility on A15 devices.

## Initial target

- Device: iPhone14,6 (iPhone SE 3rd generation)
- Current OS: iOS 26.4.2
- Target IPSW: iOS 15.4 / build 19E241

## Scope

The harness performs offline IPSW/BuildManifest inspection and compatibility reporting. It does **not** bypass Apple's signing, modify boot-chain components, generate authorization tickets, or perform a restore.

## Research questions

1. Which restore components are present in the target IPSW?
2. Which components are explicitly scoped to iPhone14,6?
3. What minimum/maximum OS and firmware relationships are expressed by the manifest?
4. Which compatibility questions require device-side measurements or publicly documented A15 research?
5. Which assumptions in A12/A13 downgrade research are architecture-specific?

## Usage

Run the validator against an extracted IPSW directory or a `BuildManifest.plist`:

```sh
python3 research/a15-legacy-restore/validate_manifest.py /path/to/BuildManifest.plist --device iPhone14,6
```

The output is intentionally diagnostic. A `PASS` result means only that the manifest is internally consistent for the requested device; it is not an indication that Apple will authorize a restore.
