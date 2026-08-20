# A15 / 19E241 SEP and Firmware Compatibility Dossier

Target: `iPhone14,6` / D49AP / A15 (`t8110`)
Target OS: iOS 15.4 (`19E241`)

This dossier tracks what the real Apple `BuildManifest.plist` proves about the target firmware set and what remains unknown about using that set in a legacy-restore scenario. It is compatibility analysis only; it does not implement SEP or restore-security bypasses.

## Verified target components

The real `19E241` manifest analysis confirms the following target-specific entries:

| Component | Manifest path / value | Status |
|---|---|---|
| SEP | `Firmware/all_flash/sep-firmware.d49.RELEASE.im4p` | VERIFIED PRESENT |
| RestoreSEP | `Firmware/all_flash/sep-firmware.d49.RELEASE.im4p` | VERIFIED PRESENT |
| iBSS | `Firmware/dfu/iBSS.d49.RELEASE.im4p` | VERIFIED PRESENT |
| iBEC | `Firmware/dfu/iBEC.d49.RELEASE.im4p` | VERIFIED PRESENT |
| iBoot | `Firmware/all_flash/iBoot.d49.RELEASE.im4p` | VERIFIED PRESENT |
| LLB | `Firmware/all_flash/LLB.d49.RELEASE.im4p` | VERIFIED PRESENT |
| DeviceTree | `Firmware/all_flash/DeviceTree.d49ap.im4p` | VERIFIED PRESENT |
| KernelCache | `kernelcache.release.iphone14c` | VERIFIED PRESENT |
| Baseband | `Firmware/Mav30-1.00.04.Release.bbfw` | VERIFIED PRESENT |

Both Apple restore identities are present. The erase/update identities differ in `RestoreRamDisk` and `RestoreTrustCache`; the other critical component paths match.

## SEP questions that remain unresolved

| Question | Required evidence | Status |
|---|---|---|
| Can the `19E241` SEP firmware initialize correctly in the proposed restore environment? | Independent A15/D49AP compatibility evidence | UNKNOWN |
| Does the relevant restore path require a newer SEP/firmware pairing than `19E241` supplies? | Version-pairing evidence from public research or reproducible analysis | UNKNOWN |
| Are SEP/baseband constraints independent, or does either impose an additional minimum compatible firmware state? | Component-pairing evidence | UNKNOWN |
| Does an early-boot research primitive preserve the state needed for normal SEP initialization? | Evidence tied to the specific primitive | UNKNOWN |
| Can the erase and update identities be treated equivalently from a SEP perspective? | Restore-environment evidence | UNKNOWN |

## What the manifest proves — and does not prove

The manifest **does prove** that Apple shipped a complete D49AP production firmware set for iOS 15.4, including target SEP, baseband, boot-chain, kernel, and restore components.

It **does not prove**:

- that a device currently running a much newer OS can be authorized to install that set;
- that SEP state created by a newer environment can be safely transitioned to the older target;
- that target SEP/baseband versions remain mutually compatible with whatever restore environment would be used;
- that possessing a boot primitive automatically resolves SEP compatibility.

## Compatibility gates

The project should not promote SEP status from `UNKNOWN` until all of the following are independently supported:

1. **Retail A15 early-boot capability exists.**
2. **The capability reaches a stage where the target restore chain can be meaningfully evaluated.**
3. **Target `19E241` SEP initialization/hand-off is demonstrated or otherwise independently established on D49AP.**
4. **Baseband compatibility is checked separately rather than inferred from SEP success.**
5. **Erase vs. update restore-identity differences are accounted for.**

## Current disposition

**SEP COMPATIBILITY: UNKNOWN / SECONDARY BLOCKER.**

The primary blocker remains missing retail A15 early-boot control. SEP becomes the next decisive compatibility gate only after that prerequisite exists.
