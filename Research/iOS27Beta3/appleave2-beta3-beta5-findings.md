# AppleAVE2: iOS 27 beta 3 vs beta 5 findings

Target:

- Device: `iPhone17,3`
- Target build: `24A5380h` (iOS 27 beta 3)
- Comparator: `24A5408d` (iOS 27 beta 5)
- Beta-3 IPSW SHA-256: `330af26dd2035017c9f0290f669c7844edb3b6f5a616a0521c24ebd46e7fb32a`
- Beta-5 IPSW SHA-256: `ed421d61200bbe90358e3f0065b81296dfc91882636dedd2b2880b3e48bca523`

This document records static firmware evidence only. It deliberately distinguishes observed binary changes from any claim that a particular CVE is present or exploitable on the target.

## AppleAVE2 version change

- beta 3: `com.apple.driver.AppleAVE2` version `913.8.0`
- beta 5: `com.apple.driver.AppleAVE2` version `913.43.1`

Reconstructed/extracted KEXT Mach-O hashes and UUIDs are intentionally not treated as stable firmware identity here because those values may depend on extraction/reconstruction behavior. The build numbers, source IPSW hashes, KEXT versions, and semantic code differences are the stronger comparison anchors.

## Function-start inventory

The extracted function-start inventories contain:

- beta 3: 2,994 start addresses
- beta 5: 2,995 start addresses

A raw adjacent-function-size comparison shows broad code churn, but index-only comparisons can be misleading after insertion/deletion/reordering. Named-function mapping corrected one earlier interpretation:

- beta 3 `AVE_CHM_GetMCTFOutBuf`: relative start `0x4aa4c`, size `0x47c`;
- beta 5 `AVE_CHM_GetMCTFOutBuf`: relative start `0x4f804`, size `0x3d0`.

The function therefore did **not** disappear in beta 5; it moved in the function-start sequence and became smaller/restructured. Relative offsets are patch-localization aids only, not runtime exploit offsets.

## Highest-signal arithmetic hardening: `AVE_CalcBufSizeOfCodedData`

A stronger semantic change appears in the coded-data buffer-size calculation path.

### beta 3

- relative start: `0x3bcac`
- size: `0x47c`
- the dimension product is formed using a 32-bit multiply before the later sizing/range logic:

```asm
mul w9, w22, w21
```

### beta 5

- relative start: `0x3c154`
- size: `0x558`
- beta 5 first computes the product as a 64-bit signed value and validates it before continuing:

```asm
smull x25, w4, w3
lsr   x8, x25, #0x1f
cbnz  x8, <overflow-error-path>
```

The beta-5 function also references validation text equivalent to:

- `iPixelArea >= 0 && iPixelArea <= 2147483647`
- a `pixel area overflow` diagnostic containing the input dimensions and computed product.

Static call-xref analysis found three internal callers of `AVE_CalcBufSizeOfCodedData` in both beta 3 and beta 5. That makes this a live internal sizing path rather than an obviously dead diagnostic helper.

### Interpretation

This is concrete evidence of integer-overflow hardening between `24A5380h` and `24A5408d`: beta 5 checks the width/height-derived product in 64-bit space before allowing the calculation to proceed through the legacy 32-bit sizing logic. It is a high-value root-cause candidate, **not** proof that the beta-3 path is reachable from an unprivileged app with attacker-controlled dimensions or that it yields a kernel primitive.

## Other beta-5 validation / overflow additions

After stripping virtual addresses and comparing only string values, beta 5 contains many validation strings absent from beta 3. Security-relevant additions include diagnostics/assertions for:

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

Other named functions with substantial beta-5 growth/hardening include:

- `AVE_CHM_SetDataInfo_FwBuf`
- `AVE_Client_CheckInfo`
- `AVE_CreateDataSurfaces`
- `AVE_DARTMapDataSurfaces`

These are secondary candidates until their individual semantic deltas and call paths are characterized as precisely as `AVE_CalcBufSizeOfCodedData`.

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

## Overall interpretation

AppleAVE2 received substantial size-validation and overflow-hardening changes between `24A5380h` and `24A5408d`. The `AVE_CalcBufSizeOfCodedData` arithmetic change is currently the clearest localized semantic delta.

This makes AppleAVE2 a higher-signal subsystem for the beta-3 kernel research track than it was from advisory text alone. It does **not**, by itself, prove that the changes correspond to a particular CVE or that a vulnerable input path is reachable from the Dopamine app on `24A5380h`.

## Next validation steps

1. Map the three internal callers of `AVE_CalcBufSizeOfCodedData` to their higher-level AVE operations.
2. Use the existing reachability-only device probe to establish whether `AppleAVE2Driver` is published and whether the default user client can be opened on `24A5380h`.
3. Map newly added beta-5 overflow/validation strings to their containing functions and corresponding beta-3 implementations.
4. Add rejection-only device checks for ordinary/boundary inputs after the relevant public/user-client operation is identified; avoid treating an intentionally corrupting payload as necessary evidence.
5. Treat reachability, rejection differences, or a reproducible crash as evidence for deeper manual validation; do not mark a kernel primitive as available until stable kernel read/write or execution is independently demonstrated.
