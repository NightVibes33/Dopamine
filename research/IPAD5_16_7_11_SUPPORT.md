# iPad 5 (iPad6,11 / iPad6,12) on iOS 16.7.11 — support lab

## Baseline

This branch starts exactly at official Dopamine 2.5 Beta 3 commit:

`53d75cff78f0fa71e4a366c6287b32ad01e8b6d1`

No iPad-specific race timing, heap geometry, socket spray, or cleanup modifications are applied on this branch until they are isolated and measured.

## What is already supported upstream

- DarkSword's exploit metadata includes iOS 15.0 through 18.7.1 and excludes A8 only.
- iPad6,11 / iPad6,12 use A9 and therefore pass the upstream exploit-selection gate.
- Dopamine 2.5 Beta 3 release notes declare arm64 support for iOS 16.7 through 16.7.16.
- The 2 GB RAM limitation documented by upstream applies to iOS 17.0 or later, not iOS 16.7.x.

Therefore this device/version is not missing a simple compatibility-plist entry. The remaining problem is exploit reliability and runtime duration on this hardware.

## Evidence from the iPad report

The supplied report is a nonfatal excessive-CPU diagnostic, not a conventional crash:

- iPad6,11, iOS 16.7.11 (20H360)
- two active CPUs
- 90 seconds CPU during 149 seconds wall time
- 61% average process CPU
- footprint increased by about 342 MB
- the hot call path enters the dynamically loaded exploit image and kernel syscalls

The pattern is consistent with DarkSword's two-thread race:

1. the main exploit thread repeatedly performs the pwritev/preadv + mach_vm_map race;
2. the free thread busy-polls shared synchronization flags;
3. the mapping scan can run long enough to cross the iOS CPU diagnostic window.

## Upstream search cost

The non-A18 path uses:

- `totalSearchMappingPagesNum = 0x10000` (65,536 pages)
- `searchMappingSize = 0x2000 * PAGE_SIZE`
- on a 16 KB page device: eight 128 MB mappings, one GB total search coverage
- a 22,528-socket spray

A public DarkSword trace scanned one 8,000-page mapping in about 20 seconds. A worst-case eight-mapping pass is therefore roughly 160 seconds, close to the 149-second CPU report from this iPad.

## Confirmed upstream defects / risks

1. Search mappings are retained through `surface_mlock()` but upstream cleanup deallocates the VM mapping without calling `surface_munlock()` for non-A18 devices. This can retain IOSurface objects across failed passes.
2. `physical_oob_read_mo_with_retry()` retries forever.
3. socket-pointer corruption retries forever.
4. the outer heap-layout pass retries forever.
5. the race synchronization uses intentional busy polling. Replacing those waits with arbitrary `usleep()` calls can reduce CPU but can also destroy race reliability.

## Correct engineering strategy

Do not change multiple exploit variables in one build. Produce three independently identifiable builds:

### A. Stock control

- exact official 2.5 Beta 3 DarkSword code
- development signed using the same profile/certificate
- no additional logging in race-critical paths

Purpose: determine whether upstream already works on this exact device when our prior patches are absent.

### B. Observation build

Preserve stock exploit behavior and add only low-overhead diagnostics:

- source SHA, executable UUIDs, build number
- device model, OS build, page size, CPU count, memory metrics
- pass number and elapsed wall/CPU time
- mapping index and pages scanned, sampled every 512 or 1,024 pages
- race success count
- first PCB candidate and rejection reason
- stage markers for socket corruption, early KRW, kernel base, patchfinding, bootstrap
- in-memory ring buffer; flush only at mapping/pass boundaries
- archive dSYMs and a UUID-to-binary map for every Mach-O image

Purpose: identify the exact stage and mapping where this iPad stalls without perturbing the race.

### C. iPad 5 bounded-pass flavor

Only after A/B data, add a dedicated `ipad5-16.7` flavor selected for iPad6,11/iPad6,12 on 16.7.x:

- keep inner race timing unchanged;
- release each scanned mapping immediately after it is ruled out;
- call `surface_munlock()` before `mach_vm_deallocate()`;
- cap a heap-search pass by elapsed time or mapping count, then fully clean up and respray;
- bound OOB-read and corruption retries and propagate a recoverable failure;
- keep UI responsive and report a retry instead of allowing an infinite pass;
- test mapping coverage and socket spray as a controlled matrix rather than hardcoding one guess.

Initial test matrix:

| Profile | Search coverage | Mapping size | Maximum mappings scanned per pass | Socket spray |
|---|---:|---:|---:|---:|
| stock | 1 GB | 128 MB | 8 | 22,528 |
| bounded-4 | 1 GB allocated | 128 MB | 4 | 22,528 |
| lowmem-512 | 512 MB | 64 MB or 128 MB | 4–8 | 18,432 / 20,480 / 22,528 |

Every test must record success/failure stage, elapsed time, CPU diagnostic occurrence, peak footprint, race-success rate, and number of attempts.

## Acceptance criteria

Support is considered real only when the same build on iPad6,11 / 20H360:

1. reaches early kernel read/write repeatedly;
2. reaches patchfinding and bootstrap, not just exploit completion;
3. succeeds across at least 10 cold attempts with a recorded success rate;
4. never grows memory monotonically between failed passes;
5. returns a visible recoverable error before the CPU diagnostic window when a pass fails;
6. ships with dSYM/UUID artifacts so every future report can be symbolicated.

## Immediate next build order

1. Stock control.
2. Observation build with dSYMs.
3. Compare logs.
4. Only then enable the bounded-pass iPad flavor.
