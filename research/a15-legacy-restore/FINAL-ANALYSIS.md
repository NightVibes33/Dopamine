# Final Analysis — iPhone14,6 → iOS 15.4 (19E241)

## Result

The firmware side of the question is resolved. The actual Apple `BuildManifest.plist` for `iPhone14,6_15.4_19E241_Restore.ipsw` was extracted directly from the Apple CDN by HTTP byte range and parsed successfully in GitHub Actions.

Verified workflow run: `32402473440`

Verified artifact: `9418990839` (`iPhone14-6-19E241-manifest-analysis`)

Artifact digest: `sha256:941ca6f70e6e376eab34eb2a5df0143ea1d8f43a681ce054f4aa7444c4c12a88`

## Target identity

- Product: `iPhone14,6`
- Marketing device: iPhone SE (3rd generation)
- Board: `D49AP`
- SoC/platform: A15 / `t8110`
- CPID: `0x8110`
- BDID: `0x10`
- Target OS: iOS 15.4
- Build: `19E241`
- IPSW SHA-256: `b75a78bb659277461189946838573eae5eee1a540737c4a681058603cdf3523b`

## BuildManifest findings

- `SupportedProductTypes` includes `iPhone14,6`.
- Two D49AP hardware identities match by `DeviceClass` and CPID+BDID.
- Identity 0 is `Customer Erase Install (IPSW)` / `RestoreBehavior=Erase`.
- Identity 1 is `Customer Upgrade Install (IPSW)` / `RestoreBehavior=Update`.
- Each identity contains 80 components, 160 matrix rows total.

Critical target components are present:

| Component | Target path |
|---|---|
| LLB | `Firmware/all_flash/LLB.d49.RELEASE.im4p` |
| iBSS | `Firmware/dfu/iBSS.d49.RELEASE.im4p` |
| iBEC | `Firmware/dfu/iBEC.d49.RELEASE.im4p` |
| iBoot | `Firmware/all_flash/iBoot.d49.RELEASE.im4p` |
| iBootData | `Firmware/all_flash/iBootData.d49.RELEASE.im4p` |
| SEP / RestoreSEP | `Firmware/all_flash/sep-firmware.d49.RELEASE.im4p` |
| DeviceTree | `Firmware/all_flash/DeviceTree.d49ap.im4p` |
| Kernel / RestoreKernel | `kernelcache.release.iphone14c` |
| Baseband | `Firmware/Mav30-1.00.04.Release.bbfw` |

The erase/update identities share the same paths for the boot-chain, SEP, DeviceTree, kernel and baseband components. Their path-level difference is limited to the restore ramdisk and matching trust cache:

- Erase: `018-27291-345.dmg`
- Update: `018-27148-345.dmg`

A concise machine-readable record is committed at `data/19E241/manifest-summary.json`.

## Public capability comparison

Current public `surrealra1n` documentation covers A12/A13 iPhones but does not document A15 support.

Public `usbliter8` material describes an A12/A13 SecureROM research primitive and lists the SE 2/A13 among supported targets; the reviewed support information does not establish an SE 3/A15 equivalent.

There is public A15 TXM/SPTM patch-analysis work, including SE 3 references. That is useful downstream platform research but does not itself provide SecureROM/DFU entry or equivalent earliest-stage boot authority. It therefore does not close the A12/A13 → A15 portability gap.

## Feasibility verdict

**The iPhone SE 3 / A15 downgrade to iOS 15.4 is not currently demonstrated by the public techniques reviewed in this project.**

The reason is no longer uncertainty about the IPSW. `19E241` is definitively an authentic D49AP target firmware with the expected A15 restore and boot components.

The decisive missing capability is a publicly established A15 early-boot primitive capable of providing the class of control needed before a tethered unsigned restore architecture can become viable. SEP/firmware compatibility and restore authorization remain subsequent unresolved dependencies.

This verdict means “no currently demonstrated public path,” not “theoretically impossible.”

## Research boundary

The branch now completes the non-destructive work that can be validated independently: target verification, real-manifest extraction, hardware identity matching, component inventory, A13→A15 dependency analysis, public-capability cross-checking, tests, and CI artifacts. It does not implement or operationalize a signing bypass, SecureROM exploit, SEP compromise, or device-security bypass.
