# A15 Legacy-Restore Feasibility

## Target

- Device: `iPhone14,6` — iPhone SE (3rd generation)
- Board: `D49AP`
- Platform/SoC: `t8110` / A15
- CPID: `0x8110`
- BDID: `0x10`
- Target OS: iOS 15.4 (`19E241`)
- Project starting OS: iOS 26.4.2

## Verified firmware facts

- Target IPSW: `iPhone14,6_15.4_19E241_Restore.ipsw`.
- SHA-256: `b75a78bb659277461189946838573eae5eee1a540737c4a681058603cdf3523b`.
- The IPSW is unsigned by Apple's normal restore service.
- The exact Apple CDN object is recorded in `target-profile.json`.

## Real Apple BuildManifest result

The automated range-fetch pipeline successfully extracted and parsed the actual Apple `BuildManifest.plist`.

- `ProductVersion`: `15.4`
- `ProductBuildVersion`: `19E241`
- `SupportedProductTypes`: `iPhone14,6`
- Build identities: `2`
- Verified D49AP matches: `2`
- Both matches identify CPID `0x8110`, BDID `0x10`, and `DeviceClass=d49ap`.
- Identity 0: `Customer Erase Install (IPSW)` / `RestoreBehavior=Erase`.
- Identity 1: `Customer Upgrade Install (IPSW)` / `RestoreBehavior=Update`.
- Each identity contains 80 manifest components.
- Production iBSS, iBEC, iBoot, LLB, SEP, RestoreSEP, DeviceTree, kernel, restore-kernel, baseband, and restore-ramdisk entries are present.
- The two identities use the same boot-chain, SEP, DeviceTree, kernel and baseband paths. Their path-level difference is the erase-vs-update restore ramdisk and matching trust cache.

The target-IPSW/device-identity question is therefore fully resolved: `19E241` is genuinely packaged for the SE 3 / D49AP hardware.

## Tooling status

| Stage | Status |
|---|---|
| Verified hardware profile | DONE |
| Correct BuildManifest identity matching (DeviceClass + CPID/BDID) | DONE |
| HTTP-range extraction of `BuildManifest.plist` | VERIFIED WORKING |
| Offline manifest validator | VERIFIED WORKING |
| Structured report generator | VERIFIED WORKING |
| Component matrix generator | VERIFIED WORKING |
| Synthetic unit tests, including HTTP-range ZIP extraction | PASS |
| GitHub Actions real-manifest analysis | PASS |
| Restore authorization bypass | NOT ESTABLISHED |
| A15 SecureROM/DFU primitive | NOT ESTABLISHED |
| A15 SEP compatibility workaround | NOT ESTABLISHED |

Verified run: `32402473440`; artifact `9418990839`; artifact digest `sha256:941ca6f70e6e376eab34eb2a5df0143ea1d8f43a681ce054f4aa7444c4c12a88`.

## Decisive architecture gap

The public reference downgrade route (`surrealra1n`) documents A12/A13 iPhone support, not A15. Public `usbliter8` SecureROM research describes an A12/A13-class primitive, including SE 2/A13, but not SE 3/A15.

There is separate public A15 TXM/SPTM patch-analysis work that includes SE 3 references. That is useful evidence that later A15 boot/runtime structures are being analyzed, but it does **not** provide the missing earlier SecureROM/DFU entry primitive. It therefore does not make the A12/A13 downgrade chain portable to A15 by itself.

That gap is upstream of IPSW parsing. The real manifest proves that all expected D49 production components exist; it does not provide a way to make an unsigned restore chain execute on A15.

## Current conclusion

**NOT CURRENTLY POSSIBLE WITH THE PUBLICLY DOCUMENTED TECHNIQUES REVIEWED BY THIS PROJECT.**

This is not a claim that an A15 downgrade is theoretically impossible. It means the presently public A12/A13 `usbliter8` / `surrealra1n` route cannot simply be ported to `iPhone14,6`, because no equivalent public A15 SecureROM/DFU capability has been established.

The decisive missing capability is an A15-class primitive that provides the boot/restore control the A12/A13 method obtains from `usbliter8`, followed by independent SEP/firmware compatibility evidence. The actual `19E241` manifest is no longer an unknown.

## Safety / research boundary

This branch performs firmware metadata collection, compatibility analysis, source comparison, and reproducible validation. It does not implement a signing bypass, SecureROM exploit, SEP compromise, or device-security bypass.
