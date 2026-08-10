# iPhone 11 iOS 27 research -> iPhone 16 / A18 portability

Target branch: `iphone16-ios27-v2`
Target firmware: iPhone17,3 / A18 / iOS 27 beta 3 `24A5380h`

## What transfers

The public A12/A13 iOS 27 ramdisk research uses a boot-chain entry and then patchfinds SPTM/TXM/kernel policy. The A12/A13 SecureROM entry itself is not an A18 primitive, but the downstream iOS 27 SPTM/TXM structures are useful reference material for A18.

Reference patchfinders were pinned to:

`Pa7r0n/ICH_A12_plus_Ramdisk@b3c2db8d160c94d802393b87d0377f3623fff54b`

They were run offline, without an output path, against raw A18 iPhone17,3 SPTM/TXM images extracted from beta 3, beta 4, and beta 5.

## A18 beta 3 result

### TXM

The public TXM patchfinder exits successfully on the A18 beta-3 TXM and identifies all major policy/code-signing targets it expects:

- device type initialization
- six policy flag stores
- cdhash loader
- `get-task-allow`
- dynamic codesigning
- pmap trust

It proposes **15 in-memory patches**. This proves strong static portability of the downstream TXM patchfinding logic. It does not prove those patches can be applied to a running A18 device.

### SPTM

The public SPTM patchfinder exits successfully but is only partially portable:

- `sptm_determine_kernel_ctrr` resolves and receives its two proposed instructions.
- key functions including the XNU read-only page-table path, SPTM init, AMCC checks, lock-regs device-tree handling, and bootstrap unmap are discovered.
- the older `ctrr_lock_boot` routine is not found.
- the older `cpu_lock_system_registers` routine is not found.

The A18 beta-3 SPTM contains `ctrr_lock_sptm` instead. Static mapping places it at file offset `0xb7afc` / VA `0xfffffff0270bbafc`, size `0x164`. The function contains system-register accesses/writes and calls CTRR group validation routines, indicating the older lock responsibilities were reorganized rather than simply absent.

The same `ctrr_lock_sptm` structure persists in beta 4 and beta 5, with expected address/size movement as the firmware changes.

## Implication

The iPhone 11 work can accelerate the **post-entry** A18 work, especially TXM and SPTM patchfinding. It cannot provide the missing A18 entry primitive.

For an app-based Dopamine-style A18 chain, the working model remains:

1. app-reachable kernel entry / stable kernel R/W
2. A18 runtime SPTM leverage/bypass
3. TXM/code-signing/trust path
4. Dopamine privilege/bootstrap/userspace stages

The AppleAVE2 beta3 -> beta4 size-validation diff is currently the strongest kernel-entry research candidate on this branch. The SPTM runtime primitive remains the major second blocker.

## Safety / validity gates

- Do not widen exploit manifests to call unsupported code.
- Do not treat offline boot-image patches as a runtime SPTM bypass.
- Do not claim a jailbreak until the chain succeeds on physical hardware through reboot/re-jailbreak testing.
