# Paleramine: No-PC palera1n-compatible environment inside Dopamine

## Goal

Create a semi-untethered, on-device jailbreak path for iPad6,11 / iPad6,12 on iOS 16.7.11 that reuses selected palera1n device-side components without requiring DFU, USB hosting, a computer, or another device.

This is not a self-hosted checkm8 implementation. The iPad cannot remain the USB host after it reboots into DFU. The invention replaces palera1n's DFU/checkm8/Pongo entry with an in-iOS kernel entry, then adapts compatible post-exploit components.

## Architecture boundary

### Cannot be reused directly

- checkm8 / checkra1n USB transport
- DFU and recovery orchestration
- PongoOS bare-metal runtime
- pre-boot ramdisk injection
- boot arguments that must be set before XNU starts
- patches that only work before kernel initialization

### Candidate components to adapt

- KPF userland patchfinder logic
- palera1n rootless bootstrap layout under Preboot
- jbinit concepts and service definitions
- binpack / Procursus package payload
- loader and force-revert UX
- safe-mode state and boot-environment metadata
- compatibility tests for A9 / iOS 16.7.x

## Proposed runtime

1. Dopamine validates iPad6,11 or iPad6,12, A9, arm64, and iOS 16.7.x.
2. An in-iOS kernel exploit acquires the minimum stable kernel read/write primitive.
3. Dopamine obtains the exact kernelcache for build 20H360 and calculates the live kernel slide.
4. A LiveKPF adapter runs patchfinder logic in analysis-only mode and produces a patch plan.
5. The adapter classifies every proposed patch as live-safe, already covered by Dopamine, or preboot-only.
6. Dopamine applies only live-safe changes through its kernel primitives.
7. A bootstrap adapter installs a palera1n-compatible rootless environment in a dedicated Preboot directory.
8. Dopamine injects or starts the required launchd hooks using its existing userspace-jailbreak path.
9. The device performs a userspace reboot, not a DFU or cold boot.
10. After a full reboot, the user opens Dopamine and repeats the in-iOS entry, making the result semi-untethered.

## LiveKPF safety model

The first implementation must never write patches. It should:

- parse the exact kernelcache
- find candidate offsets
- calculate live addresses from the kernel slide
- read the current live bytes
- compare expected and actual bytes
- record a signed patch-plan report
- reject unknown or mismatched instructions

Write mode is enabled only after a patch is proven to be valid for 20H360 and is safe to apply after XNU has fully booted.

## Patch classes

### Class A: reuse Dopamine implementation

Use Dopamine's existing mechanisms for:

- kernel read/write initialization
- trust cache handling
- root and sandbox changes
- launchd interaction
- rootless bootstrap activation
- userspace reboot

### Class B: adapt from palera1n

Research and port only where it improves A9 / iOS 16.7.11 behavior:

- bootstrap layout and metadata
- jbinit service configuration
- safe mode and force-revert state
- loader environment management
- compatibility checks

### Class C: reject for live application

Do not attempt to apply from a running iOS app:

- early-boot page-table patches whose assumptions no longer hold
- ramdisk mount hooks that must run before root filesystem initialization
- boot-argument changes
- code that expects PongoOS physical-memory mappings
- checkm8 or USB control-transfer stages

## Main blocker

Paleramine still needs a reliable in-iOS kernel entry after every cold reboot. Palera1n cannot replace that stage because its entry occurs in DFU from an external USB host.

For iPad5 support, the immediate engineering priorities are:

1. Build the stock-behavior observation profile for DarkSword.
2. Determine whether failure occurs during race acquisition, PCB location, socket corruption, kernel-base search, patchfinding, or bootstrap.
3. Stabilize or replace only the failing entry stage.
4. Add LiveKPF in read-only analysis mode.
5. Build the bootstrap adapter after stable kernel access is proven.

## Success criteria

Paleramine is considered viable when it can:

- obtain repeatable kernel read/write on iPad6,11 / 20H360
- produce a deterministic LiveKPF patch plan
- install and remove a dedicated rootless bootstrap safely
- complete userspace reboot into a functional jailbreak environment
- return to stock after a normal reboot
- recover cleanly from partial installation
- preserve panic, CPU, memory, and stage logs for every attempt

## Non-goals

- untethered persistence across cold reboot
- self-hosted DFU/checkm8
- writing bootrom, SEP, baseband, or AOP firmware
- modifying permanent device firmware
- applying unverified kernel patches
