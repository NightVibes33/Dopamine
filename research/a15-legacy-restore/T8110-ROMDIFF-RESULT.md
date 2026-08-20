# T8110 SecureROM A0 → B0/B1 Structural Diff Result

Source pair:

- A15 A0: `SecureROM for t8110si, iBoot-6338.0.0.200.15`
- A15 B0/B1: `SecureROM for t8110si, iBoot-6338.0.0.200.19`

Both public Git objects were pinned and verified before comparison. The binary objects are not stored in this repository or uploaded as CI artifacts.

## Verified binary facts

| Property | A0 | B0/B1 |
|---|---|---|
| Size | 1,048,576 bytes | 1,048,576 bytes |
| SHA-256 | `b19bda46a64cfe7ea7745e4d6c13665bd6afa568eac9471827a1bb54c13d7185` | `97c0b0f59cf5b2db89c1da420d7fb291ba0ba0b9567c38a70135b4f4c90e559b` |
| Catalog iBoot | `6338.0.0.200.15` | `6338.0.0.200.19` |

## Structural delta

- Changed bytes: **123,442 / 1,048,576** (**11.77%**).
- 4 KiB same-position chunk similarity: **206 / 256 = 80.47%**.
- Changed-range count: **11,442**.
- The final meaningful changed byte is below approximately `0x34652`; the large tail after that point is unchanged.
- Printable-string sets are nearly identical: 73 shared strings, 2 added, 2 removed. One deliberate string delta is the iBoot version identifier.

### Changed-byte concentration by 64 KiB region

| File-offset region | Changed bytes | Density |
|---|---:|---:|
| `0x00000–0x10000` | 15,609 | 23.8% |
| `0x10000–0x20000` | 61,528 | 93.9% |
| `0x20000–0x30000` | 45,579 | 69.5% |
| `0x30000–0x40000` | 726 | 1.1% |

The strongest delta therefore sits in the middle of the populated ROM image rather than in padding or string tables.

## Largest contiguous changed ranges

Examples from the raw structural diff:

- `0x2ede5–0x2f102`: 797 bytes
- `0x2dcc1–0x2deca`: 521 bytes
- `0x1de40–0x1dfca`: 394 bytes
- `0x280b6–0x28222`: 364 bytes
- `0x2e136–0x2e28e`: 344 bytes

These offsets are **triage anchors only**. A changed range does not imply a vulnerability or even executable code.

## Interpretation

This is a useful signal because A0 → B0/B1 is an intra-generation comparison. The hardware architecture is the same, so concentrated code-region changes are better research anchors than an A13 → A15 whole-generation diff.

The next static pass should determine which changed regions decode as ARM64 instructions and classify their control-flow/invariant changes. Priority goes to changed regions that can be associated with:

1. USB/DFU state handling,
2. DART setup and DMA isolation,
3. immutable-image parsing/validation,
4. allocator/task/error paths,
5. production/development gating.

No exploitability conclusion is made from the structural diff alone.

## Reproducibility

GitHub Actions run `32404140543` successfully:

- fetched both pinned public T8110 ROM objects;
- verified their Git blob identities;
- generated the structural diff;
- deleted the ROM binaries before artifact upload;
- uploaded only the analysis output.

Artifact: `9419604703`, digest `sha256:7dd736f47c8dbb8b8351e5961862f0b2059a95e664c6638217312089278e7799`.
