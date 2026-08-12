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
   - Current exact-build evidence: `AppleAVE2` changes across beta 3, beta 4, and beta 5. A beta-3 sizing path uses a 32-bit multiply; the corresponding beta-4 path uses signed 64-bit multiplication and an immediate range-failure branch. A separate function-level comparison also found a beta-3 path without a wide-size guard where beta 4 has one.
   - Important limitation: the known fixed iOS 26.6 comparison binary has not yet produced a matching public function/patch anchor tying those changes specifically to CVE-2026-64747. Treat this as a strong AVE hardening lead, not a proven CVE mapping or kernel primitive.

2. **CVE-2026-43805 — IOKit**
   - Published impact: application may be able to write kernel memory.
   - Priority reason: a kernel-write primitive is directly useful to a Dopamine-style kernel stage if it can be made stable on the target device.
   - Current status: exact beta-3 kernel/KEXT inventory is available, but there is still no trustworthy public vulnerable-function, crash, or patch anchor mapping this CVE to a specific target function.

3. **CVE-2026-64751 — Kernel**
   - Published impact: application may be able to write kernel memory.
   - Priority reason: use-after-free class kernel-write candidate.
   - Current status: exact beta-3 kernelcache is available, but the public function/object-lifecycle patch anchor remains missing.

4. **CVE-2026-64709 — Kernel**
   - Published impact: application may be able to disclose kernel memory.
   - Priority reason: potentially useful as an address/ASLR information primitive when paired with a write or execution bug.
   - Current status: exact beta-3 kernelcache is available, but the disclosure path has not yet been mapped to a public function/crash/patch anchor.

## Exact beta 3 -> beta 5 kernel validation

The `ios27-beta3-firmware-validation.yml` workflow completed successfully for:

- target: `iPhone17,3` / `24A5380h`
- comparator: `iPhone17,3` / `24A5408d`

Kernelcache SHA-256:

- beta 3: `c47d145cbd8c7af64ed2cf8e603ad40b7a3a322e03f32c56fa01ba5d3d62db45`
- beta 5: `8df05a835760512ec01940e7d4b0ddbc83ff9541bf1cef1e223ea953007d474c`

The extracted KEXT comparison found 306 changed KEXT payload hashes, with no unchanged extracted KEXT payloads in that comparison. That means hash-level change alone is too broad for CVE attribution.

Priority components confirmed changed include:

- `com.apple.driver.AppleAVE2`
- `com.apple.iokit.IOGPUFamily`
- `com.apple.iokit.IOSurface`
- `com.apple.AGXG17P`
- `com.apple.AGXFirmwareKextRTBuddy64`
- multiple IOKit-family KEXTs

Selected exact component hashes:

### AppleAVE2

- beta 3: `02923aca48fe13307c9d3584408b01d15318bbb74f537bc28c4506e39c602809`
- beta 5: `a01a5358493a9e4f4ba5d891a28152c17fdd8135fd6eccfbe62241ac71832294`

### IOGPUFamily

- beta 3: `2d8d1ecb23d5d11327fb3370c4c92134d0d96778ec26e9f332d2cbf7afbfaf4f`
- beta 5: `b9dadd9be8e135fb74c9d902895cdfd739b85275834e2ba15fdd0e9855ff190a`

### IOSurface

- beta 3: `dea49b2b82f7656a3a6a882ad86ff0fb5e95f56afff200deb804ffa4f3a9ff46`
- beta 5: `3faa0ecc34d6008ba0c8b987ade9861336836a13c1a3604765e59399efd0702d`

### AGXG17P

- beta 3: `3137052711822e606e8afc0fa1550100fd5ad9f780240333345768e5b0e8c7d4`
- beta 5: `ec347ad366b798c45893959c7d948ce7d12a44d3a5efd7706057860c666a5a7d`

## AVE arithmetic-hardening evidence

Existing static analysis identified this beta-3 -> beta-4 change in a CodedData sizing path:

- beta-3 sizing function: `0xfffffff0086b42ac`, size `0x47c`
- beta-3 frame-area calculation: 32-bit `mul` at `0xfffffff0086b4354`
- beta-4 sizing function: `0xfffffff0086c8e54`, size `0x558`
- beta-4 frame-area calculation: signed 64-bit `smull` at `0xfffffff0086c8e98`
- beta-4 range-failure branch: `0xfffffff0086c8ea0`

A second AppleAVE2 function-level comparison at function index 493 found:

- beta 3: 164 instructions, 0 64-bit ops, 125 32-bit ops, no detected wide-size guard
- beta 4: 259 instructions, 91 64-bit ops, 39 32-bit ops, detected wide-size guard

This is strong evidence of arithmetic/size-validation hardening between the target build and beta 4. It does **not** by itself prove controllable kernel corruption, stable kernel R/W, or that the changed function is CVE-2026-64747.

## Lower-priority / misleading leads

- **CVE-2026-43724**: real kernel-memory-write research exists publicly, but Apple fixed it before the target beta-3 build shipped. Treat it as exploitation-pattern reference material unless binary evidence shows the target branch retained the vulnerable code.
- **CVE-2026-43723**: public demonstrations are macOS root-file-write/LPE oriented; not a substitute for iPhone kernel primitives.
- **CVE-2026-43813**: public reverse engineering indicates CloudAttestation/PCC policy behavior rather than a TrollStore-style application code-signing bypass. Do not treat it as the missing jailbreak signing primitive.

## SPTM/TXM vs SEP

For this A18-era target, the post-kernel integrity problem is primarily **SPTM/TXM**, not SEP.

SEP is a separate security processor used for sensitive key material, biometrics, passcode/data-protection operations, and related secure services. A normal rootless jailbreak does not require compromising SEP.

The practical chain under research is therefore:

`userland foothold -> kernel primitive -> stable kernel R/W or kernel execution -> SPTM/TXM-compatible post-exploitation -> trust/code-signing/bootstrap integration -> rootless jailbreak environment`

### Exact beta-3 A18 SPTM structural result

The existing `ios27-a18-sptm-txm-research.yml` workflow completed successfully for beta 3, beta 4, and beta 5. It is an offline structure/anchor scan only and does not claim a runtime bypass.

For beta 3 `24A5380h`:

- SPTM reference anchors: `11/15`
- TXM reference anchors: `8/9`
- primary A18 CTRR lock routine: file offset `0xb7afc`, confidence `high`
- secondary A18 CTRR lock routine: file offset `0xb7c60`, confidence `high`
- lock-register apply routine: file offset `0xbba64`, confidence `high`
- `sptm_determine_kernel_ctrr`: file offset `0xae540`, confidence `high`

The primary/secondary pair is structurally stable across beta 3 through beta 5, although the exact offsets move. This confirms that a kernel bug alone is not the complete A18 jailbreak path: the SPTM/TXM protection model remains a separate post-kernel engineering requirement.

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
