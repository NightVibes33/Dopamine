# A13 → A15 Dependency Scan

## Purpose

Use `dependency-scan.py` against a local checkout of the publicly available `surrealra1n` source tree to inventory hardware-generation, restore-chain, SEP, boot-mode, and version/nonce references.

## Usage

```sh
python3 research/a15-legacy-restore/dependency-scan.py \
  /path/to/surrealra1n \
  --json research/a15-legacy-restore/data/surrealra1n-dependencies.json
```

## Interpretation

The output identifies **where** A12/A13-specific assumptions occur. It does not infer that a textual reference is an exploitable primitive or a portable implementation.

For each hit, manually classify it as:

- `GENERIC` — restore plumbing that can likely be reused as research infrastructure.
- `A13_SPECIFIC` — explicitly tied to A13/device identifiers or assumptions.
- `SEP_SPECIFIC` — depends on SEP behavior and requires separate compatibility evidence.
- `UNKNOWN` — requires source-level investigation.
- `A15_RELEVANT` — explicitly mentions A15/iPhone14,6 and should be checked for existing support.

## Current public evidence

`surrealra1n` describes itself as supporting A7/A8(X), A11, and A12/A13 iPhones. It does not document A15 support. This scanner is therefore intended to locate the exact source-level assumptions behind that support boundary.
