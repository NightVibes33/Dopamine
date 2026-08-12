# iPhone 16 / iOS 27 beta 3 research track

Target device/build for this branch:

- Product type: `iPhone17,3`
- OS: iOS 27 beta 3
- Build: `24A5380h`

## Research objective

Determine which publicly disclosed post-beta-3 kernel vulnerabilities are actually present in `24A5380h`, and keep Dopamine's exploit selection honest until stable kernel primitives are demonstrated on-device.

## Existing userland footholds

### bad_query

Bundled as a userland sandbox/container preflight. The branch experimentally enables the preflight for `24A5380h` and `24A5390f` without advertising ClearSword as an iOS 27 kernel exploit.

### FilzaSlop companion

Packaged separately because the useful MobileHouseArrest MCM path requires the companion to retain the `com.apple.mobile.MobileHouseArrest` identity.

## Kernel candidate priority

The following candidates are research priorities because Apple's published impact descriptions are materially relevant to a jailbreak kernel stage. Presence on `24A5380h` is **not assumed**; firmware diffing and on-device validation must establish that first.

1. **CVE-2026-64747 — AVEVideoEncoder**
   - Published impact: application may be able to execute arbitrary code with kernel privileges.
   - Priority reason: direct kernel-code-execution class impact and AppleAVE/AVE reachability is already a relevant subsystem for this branch.
   - Required next evidence: identify the corresponding AppleAVE/AVEVideoEncoder binary changes between `24A5380h` and a later comparison build, then confirm whether the vulnerable path exists in the beta-3 binary.

2. **CVE-2026-43805 — IOKit**
   - Published impact: application may be able to write kernel memory.
   - Priority reason: a kernel-write primitive is directly useful to a Dopamine-style kernel stage if it can be made stable on the target device.
   - Required next evidence: locate the patch-bearing kernel/KEXT component and establish whether the beta-3 build predates that fix.

3. **CVE-2026-64751 — Kernel**
   - Published impact: application may be able to write kernel memory.
   - Priority reason: use-after-free class kernel-write candidate.
   - Required next evidence: isolate the changed kernel function/object lifecycle and verify presence in `24A5380h`.

4. **CVE-2026-64709 — Kernel**
   - Published impact: application may be able to disclose kernel memory.
   - Priority reason: potentially useful as an address/ASLR information primitive when paired with a write or execution bug.
   - Required next evidence: identify whether the disclosure path is present and whether it yields stable, useful kernel addresses on the target.

## Lower-priority / misleading leads

- **CVE-2026-43724**: real kernel-memory-write research exists publicly, but Apple fixed it before the target beta-3 build shipped. Treat it as exploitation-pattern reference material unless binary evidence shows the target branch retained the vulnerable code.
- **CVE-2026-43723**: public demonstrations are macOS root-file-write/LPE oriented; not a substitute for iPhone kernel primitives.
- **CVE-2026-43813**: public reverse engineering indicates CloudAttestation/PCC policy behavior rather than a TrollStore-style application code-signing bypass. Do not treat it as the missing jailbreak signing primitive.

## SPTM/TXM vs SEP

For this A18-era target, the post-kernel integrity problem is primarily **SPTM/TXM**, not SEP.

SEP is a separate security processor used for sensitive key material, biometrics, passcode/data-protection operations, and related secure services. A normal rootless jailbreak does not require compromising SEP.

The practical chain under research is therefore:

`userland foothold -> kernel primitive -> stable kernel R/W or kernel execution -> SPTM/TXM-compatible post-exploitation -> trust/code-signing/bootstrap integration -> rootless jailbreak environment`

## Automated firmware validation

Workflow:

`.github/workflows/ios27-beta3-firmware-validation.yml`

It compares `24A5380h` against `24A5408d` for `iPhone17,3` using blacktop/ipsw and produces:

- kernelcache SHA-256 values
- KEXT inventories and inventory diff
- extracted-KEXT SHA-256 comparison
- priority subsystem change list for AppleAVE/AVEVideo/IOSurface/IOKit/AGX/GPU/VideoEncoder names
- priority Mach-O UUID/build metadata
- AppleDB firmware records

A changed KEXT hash is only evidence that the component changed between builds. It is **not** sufficient to claim a CVE is present or fixed. Function-level analysis and target-device validation are still required.
