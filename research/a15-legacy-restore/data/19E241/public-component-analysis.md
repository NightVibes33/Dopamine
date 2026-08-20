# Public component analysis — iPhone14,6 / iOS 15.4 (19E241)

**Evidence type:** public firmware metadata; this is not a direct parse of the 5.6 GiB IPSW.

## Target

- Product: `iPhone14,6`
- Device: iPhone SE (3rd generation)
- SoC: A15 / T8110
- Version: `15.4`
- Build: `19E241`
- Baseband: `1.00.04`
- IPSW SHA-256: `b75a78bb659277461189946838573eae5eee1a540737c4a681058603cdf3523b`

## Publicly indexed restore components

The Apple Wiki's 19E241/iPhone14,6 firmware-key page identifies these target components:

| Component | Filename | Indexed |
|---|---|---|
| iBEC | `iBEC.d49.RELEASE.im4p` | Yes |
| iBoot | `iBoot.d49.RELEASE.im4p` | Yes |
| iBootData | `iBootData.d49.RELEASE.im4p` | Yes |
| iBSS | `iBSS.d49.RELEASE.im4p` | Yes |
| LLB | `LLB.d49.RELEASE.im4p` | Yes |
| SEP | `sep-firmware.d49.RELEASE.im4p` | Yes |

These names establish that the target firmware contains the expected D49/A15 boot-chain and SEP components. They do not establish that those components can be accepted by an A15 device running a newer OS or that Apple will authorize the restore.

## Important finding

The target IPSW is **unsigned** according to IPSW Downloads. Its manifest/component identity therefore cannot by itself provide a usable restore path through Apple's normal restore authorization process.

## Status

- Manifest identity: **strongly indicated by public firmware metadata**
- Component inventory: **partially reconstructed from public metadata**
- Exact `BuildManifest.plist` parse: **PENDING actual IPSW**
- Restore authorization: **not evaluated**
- SEP compatibility: **not established**
- A15 boot compatibility: **not established**
- Downgrade feasibility: **UNPROVEN**

## Sources

- IPSW Downloads: https://ipsw.me/download/iPhone14%2C6/19E241/
- The Apple Wiki: https://theapplewiki.com/wiki/Keys:SkyEcho_19E241_(iPhone14,6)

This file intentionally records only public metadata and does not contain an exploit, signing bypass, or device-modification procedure.
