# Actual Apple BuildManifest findings — iPhone14,6 / 19E241

Generated from the real `BuildManifest.plist` extracted by HTTP range from the Apple-hosted `iPhone14,6_15.4_19E241_Restore.ipsw`.

## Identity result

- `ProductVersion`: `15.4`
- `ProductBuildVersion`: `19E241`
- `SupportedProductTypes`: `iPhone14,6`
- Build identities: `2`
- Matching D49AP identities: `2`
- `ApChipID`: `0x8110`
- `ApBoardID`: `0x10`
- `ApSecurityDomain`: `0x01`
- `DeviceClass`: `d49ap`
- Build train: `SkyEcho`

Identity 0 is `Customer Erase Install (IPSW)` / restore behavior `Erase`.
Identity 1 is `Customer Upgrade Install (IPSW)` / restore behavior `Update`.
Each identity contains 80 manifest components.

## Critical production components confirmed

| Component | Path |
|---|---|
| iBSS | `Firmware/dfu/iBSS.d49.RELEASE.im4p` |
| iBEC | `Firmware/dfu/iBEC.d49.RELEASE.im4p` |
| iBoot | `Firmware/all_flash/iBoot.d49.RELEASE.im4p` |
| LLB | `Firmware/all_flash/LLB.d49.RELEASE.im4p` |
| SEP | `Firmware/all_flash/sep-firmware.d49.RELEASE.im4p` |
| RestoreSEP | `Firmware/all_flash/sep-firmware.d49.RELEASE.im4p` |
| DeviceTree | `Firmware/all_flash/DeviceTree.d49ap.im4p` |
| RestoreDeviceTree | `Firmware/all_flash/DeviceTree.d49ap.im4p` |
| KernelCache | `kernelcache.release.iphone14c` |
| RestoreKernelCache | `kernelcache.release.iphone14c` |
| BasebandFirmware | `Firmware/Mav30-1.00.04.Release.bbfw` |

The erase and update identities use different restore ramdisk images:

- Erase: `018-27291-345.dmg`
- Update: `018-27148-345.dmg`

## What this resolves

The target-IPSW question is resolved. iOS 15.4 / `19E241` contains real, production D49AP/A15 restore identities for the SE 3. The earlier concern that the IPSW might not contain the required device-specific firmware is false.

## What it does not resolve

Manifest validity does not create restore authorization or early-boot control. Current public evidence reviewed in this branch still provides the reference `usbliter8`/`surrealra1n` capability for A12/A13 rather than A15. Therefore the remaining blocker is an A15 early-boot primitive plus compatible SEP/restore handling, not the IPSW contents.

## Reproducibility

- Workflow run: `32402243047`
- Artifact: `9418906495` (`iPhone14-6-19E241-manifest-analysis`)
- Artifact digest: `sha256:85871e1aaf80176352071196f48a186d426a67ed971de2382760844375eaf5c9`
