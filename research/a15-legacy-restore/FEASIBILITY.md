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

- The target IPSW is `iPhone14,6_15.4_19E241_Restore.ipsw`.
- The public checksum is SHA-256 `b75a78bb659277461189946838573eae5eee1a540737c4a681058603cdf3523b`.
- The IPSW is currently unsigned by Apple's normal restore service.
- The exact Apple CDN object is recorded in `target-profile.json`.
- Public firmware metadata identifies D49/A15 boot-chain and SEP components for this build.

## Tooling status

| Stage | Status |
|---|---|
| Verified hardware profile | DONE |
| Correct BuildManifest identity matching (DeviceClass + CPID/BDID) | DONE |
| HTTP-range extraction of `BuildManifest.plist` | IMPLEMENTED |
| Offline manifest validator | IMPLEMENTED |
| Structured report generator | IMPLEMENTED |
| Component matrix generator | IMPLEMENTED |
| Synthetic unit tests, including HTTP-range ZIP extraction | IMPLEMENTED |
| GitHub Actions real-manifest analysis | IMPLEMENTED |
| Restore authorization bypass | NOT ESTABLISHED |
| A15 SecureROM/BootROM primitive | NOT ESTABLISHED |
| A15 SEP compatibility workaround | NOT ESTABLISHED |

## Decisive architecture gap

The current public downgrade path used as the reference (`surrealra1n`) documents A12/A13 iPhone support, not A15. The `usbliter8` SecureROM research it relies on is publicly documented for A12/A13 devices; the published device lists include the SE 2 (A13) but not the SE 3 (A15).

That difference is upstream of IPSW parsing. A perfectly valid `19E241` BuildManifest does not provide the missing A15 boot/restore control primitive.

## Current conclusion

**NOT CURRENTLY POSSIBLE WITH THE PUBLICLY DOCUMENTED TECHNIQUES REVIEWED BY THIS PROJECT.**

This is not a claim that an A15 downgrade is theoretically impossible. It means the presently public A12/A13 `usbliter8` / `surrealra1n` route cannot simply be ported to `iPhone14,6`, because no equivalent public A15 SecureROM/boot-chain capability has been established.

The real BuildManifest analysis remains useful for exact component inventory and reproducibility, but it is no longer the decisive feasibility blocker. The decisive missing capability is an A15-class primitive that can provide the boot/restore control the A12/A13 method obtains from `usbliter8`, followed by independent SEP/firmware compatibility evidence.

## Safety / research boundary

This branch performs firmware metadata collection, compatibility analysis, source comparison, and reproducible validation. It does not implement a signing bypass, SecureROM exploit, SEP compromise, or device-security bypass.
