# AppleAVE2: iOS 27 beta 3 vs beta 5 findings

Target:

- Device: `iPhone17,3`
- Target build: `24A5380h` (iOS 27 beta 3)
- Comparator: `24A5408d` (iOS 27 beta 5)

This document records static firmware evidence only. It deliberately distinguishes observed binary changes from any claim that a particular CVE is present or exploitable on the target.

## Binary identity

### beta 3

- KEXT: `com.apple.driver.AppleAVE2`
- Version: `913.8.0`
- SHA-256: `19a704841d4fe7f41d643594c675bbf91fa44d2be6a8061b04451c0d5e2a0694`
- UUID: `55E9419B-75D2-3921-9CCA-24FD89C4A5A3`

### beta 5

- KEXT: `com.apple.driver.AppleAVE2`
- Version: `913.43.1`
- SHA-256: `91d55564127fa17da8d61a6443433d5ca00c3cc60ce1d61aa56edb93ca224d7b`
- UUID: `8650D05F-4776-3381-8080-6DF6ED43AEF9`

## Function-start inventory

The extracted function-start inventories contain:

- beta 3: 2,994 start addresses
- beta 5: 2,995 start addresses

A sequence comparison of adjacent function sizes shows broad code churn, but two structural points are especially useful for follow-up:

- around function index ~607 the beta-3 layout contains a `0x47c`-byte function before a `0x30c0`-byte region, while the beta-5 layout transitions directly into a `0x30c0`-byte region at the corresponding point;
- around function index ~2483 beta 5 introduces an additional approximately `0xf8`-byte function before the sequence realigns with the beta-3 function-size pattern.

These are patch-localization anchors, not exploit offsets. Absolute virtual addresses differ between the builds and must not be compared directly.

## New beta-5 validation / overflow strings

After stripping virtual addresses and comparing only string values, beta 5 contains 116 strings not present in beta 3, while beta 3 contains only 8 strings absent from beta 5.

Security-relevant additions include diagnostics/assertions for:

- `DPB size overflow`
- `HSCOutput size overflow`
- `LRB size overflow`
- `MCTFOutput size overflow`
- generic `size overflow`
- `pixel area overflow`
- `frame dimension out of range`
- `invalid command slot`
- `EncType mismatch with session`
- stricter slice-number range validation

New arithmetic guards include checks equivalent to:

- signed size values must be non-negative and at most `INT32_MAX` (`2147483647`);
- pixel-area products must remain non-negative and at most `INT32_MAX`;
- width/height-derived products must remain within the signed 32-bit range;
- combined luma/chroma data/header sizes must remain non-negative with a total at most `INT32_MAX`.

## New beta-5 buffer-size helper names

The following helper names are present in beta 5 but absent from beta 3:

- `AVE_CalcBufSizeOfColoFwDataInfo`
- `AVE_CalcBufSizeOfColocated`
- `AVE_CalcBufSizeOfDPB`
- `AVE_CalcBufSizeOfEntropyCoding`
- `AVE_CalcBufSizeOfEntropyCodingHeader`
- `AVE_CalcBufSizeOfHSCOutput`
- `AVE_CalcBufSizeOfLFSOutput`
- `AVE_CalcBufSizeOfLRB`
- `AVE_CalcBufSizeOfLRSOutput`
- `AVE_CalcBufSizeOfMBInputCtrl`
- `AVE_CalcBufSizeOfMBStats`
- `AVE_CalcBufSizeOfMCTFOutput`
- `AVE_CalcBufSizeOfSTFSrcNeighborInfo`
- `AVE_CalcBufSizeOfSrcNeighborAboveFltPixel`
- `AVE_CalcBufSizeOfSrcNeighborData`
- `AVE_CalcBufSizeOfSrcNeighborFwData`
- `AVE_CalcBufSizeOfSrcNeighborInfo`
- `AVE_CalcBufSizeOfSrcNeighborLeftInfo`
- `AVE_CalcBufSizeOfSrcNeighborLeftPixel`
- `AVE_CalcBufSizeOfSrcNeighborPixel`
- `AVE_CalcBufSizeOfStaticAreaCBP0Cntr`

## Interpretation

This is strong evidence that AppleAVE2 received a substantial size-validation / overflow-hardening change between `24A5380h` and `24A5408d`.

That makes AppleAVE2 a higher-signal subsystem for the beta-3 kernel research track than it was from advisory text alone. It does **not**, by itself, prove that the changes correspond to CVE-2026-64747 or that a reachable vulnerable input exists from the Dopamine app on `24A5380h`.

## Next validation steps

1. Map each newly added overflow/validation string to its beta-5 code xrefs.
2. Identify the containing beta-5 function boundaries.
3. Match each patched beta-5 function to the corresponding beta-3 function using normalized instruction/function-size similarity rather than absolute addresses.
4. Determine the external/user-client path that reaches those functions.
5. Add a non-destructive device probe that only validates service/method reachability and input rejection behavior on `24A5380h`.
6. Treat a crash, rejection difference, or reachable old arithmetic path as evidence for deeper manual validation; do not mark a kernel primitive as available until stable kernel read/write or execution is independently demonstrated.
