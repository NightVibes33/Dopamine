# Paleramine Full Build Plan

## 0. Document purpose

This document defines a conservative engineering program for a no-PC, same-device jailbreak path for:

- Device: iPad (5th generation)
- Product identifiers: iPad6,11 and iPad6,12
- SoC: Apple A9 / arm64
- Target OS: iPadOS 16.7.11
- Darwin build: 20H360
- Page size observed on device: 16 KB
- Physical memory class: 2 GB

The project name is **Paleramine**.

Paleramine is not a self-hosted checkm8 implementation. It replaces palera1n's external DFU/checkm8/PongoOS entry with an in-iOS kernel entry supplied through Dopamine, then selectively reuses or adapts device-side ideas from palera1n.

The first priority is not feature count. It is proving each trust boundary without corrupting the live kernel, Preboot, launchd state, or the user's data.

---

## 1. Evidence-based feasibility verdict

### 1.1 Proven facts

1. The iPad 5th generation is listed by palera1n as a supported checkm8 device.
2. Dopamine 2.5 Beta 1 added DarkSword for iOS 16.7 through 16.7.15 on arm64; Beta 3 extends support and warns that the new DarkSword integration needs broad testing.
3. The official DarkSword exploit metadata accepts A9 and iOS 16.7.11.
4. Dopamine already implements:
   - exploit selection and loading;
   - kernelcache acquisition;
   - patchfinding;
   - kernel read/write initialization;
   - trust cache handling;
   - privilege and sandbox changes;
   - rootless bootstrap handling;
   - launchd interaction;
   - userspace reboot.
5. PongoOS includes a userland KPF test target for arm64, proving that at least some KPF logic can be compiled outside the bare-metal PongoOS runtime.
6. Palera1n's iPhoneOS host binary is intended for an already-jailbroken device acting as USB host for another target. It does not solve same-device DFU execution.
7. Palera1n's loader is a post-jailbreak bootstrap application, and jbinit produces the ramdisk/binpack environment consumed by the normal palera1n boot chain.

### 1.2 Strong inference from the supplied CPU report

The supplied `bug_type 202` report shows:

- approximately 61% average CPU for 149 seconds;
- 90 seconds of CPU time;
- process footprint growth from about 116 MB to 458 MB;
- two active CPU cores;
- the hottest stacks inside the DarkSword framework and kernel syscalls.

Upstream DarkSword can scan eight 128 MB search mappings on a 16 KB page device. A public diagnostic showed roughly 20 seconds to scan one mapping. A full unsuccessful pass can therefore approach the same 150-160 second interval seen in the report.

The best current hypothesis is a combined failure:

1. the desired sprayed PCB does not land in an early mapping;
2. the device performs a long full search;
3. IOSurface-backed mapping objects remain retained after unsuccessful mappings or passes;
4. the process remains CPU-active long enough for an iOS CPU diagnostic.

This remains a hypothesis until Build B records pass, mapping, race-success, retained-surface, and memory counters.

### 1.3 Hard architectural boundary

The iPad cannot reboot itself into DFU and continue running Dopamine. DFU terminates iOS and the app, making the iPad the USB target. Therefore Paleramine cannot directly reuse:

- checkm8;
- checkra1n USB transport;
- DFU/recovery orchestration;
- bare-metal PongoOS;
- pre-XNU boot arguments;
- ramdisk injection that must occur before normal iOS boot.

Paleramine must remain an in-iOS, semi-untethered jailbreak. After a full reboot, the user must open the app and run the entry again.

---

## 2. Project goals and non-goals

### 2.1 Goals

1. Produce repeatable kernel read/write on iPad6,11/iPad6,12 running 20H360.
2. Build a read-only LiveKPF compatibility analyzer for the exact kernelcache.
3. Generate a deterministic, signed patch plan before any live kernel write occurs.
4. Reuse Dopamine's existing live-safe mechanisms wherever possible.
5. Adapt only the useful device-side palera1n concepts:
   - rootless Preboot layout;
   - bootstrap metadata;
   - loader workflow;
   - safe mode;
   - force revert;
   - recovery state;
   - compatibility checks.
6. Stage every filesystem change transactionally.
7. Provide complete diagnostic provenance: source SHA, binary UUIDs, dSYMs, IPA hashes, kernelcache hash, patch-plan hash, and on-device stage log.
8. Ensure a normal reboot returns the device to a non-jailbroken state.
9. Ensure a partial installation can be detected and removed without relying on a successful jailbreak boot.

### 2.2 Non-goals

1. No self-hosted checkm8 or DFU exploit.
2. No untethered persistence across cold boot.
3. No SEP, baseband, AOP, bootrom, or permanent firmware modification.
4. No writes to unknown kernel builds.
5. No blind patch application based only on offsets.
6. No rootful fake filesystem in the first implementation.
7. No overwrite of the existing Dopamine bootstrap.
8. No automatic removal of user data.
9. No public release until repeated device testing and recovery testing pass.

---

## 3. Safety model

### 3.1 Default-deny rules

Write-capable code must refuse to run unless all of these match:

- machine is exactly `iPad6,11` or `iPad6,12`;
- OS version is exactly `16.7.11` for the first research build;
- Darwin build is exactly `20H360`;
- CPU family resolves to A9;
- process is arm64, not arm64e;
- page size is 16 KB;
- kernelcache hash matches the tested allowlist;
- live kernel UUID matches the kernelcache used for analysis;
- patch-plan schema and signature validate;
- every expected instruction/data byte matches live memory;
- battery is not critically low;
- free disk space meets the bootstrap staging requirement;
- no conflicting jailbreak environment is active;
- no incomplete Paleramine transaction requires recovery.

Any mismatch must result in read-only diagnostics, not a best-effort write.

### 3.2 Never-write areas in early milestones

Until explicitly unlocked by a later decision gate, Paleramine must not modify:

- bootrom or iBoot storage;
- SEP/baseband/AOP firmware;
- APFS container metadata directly;
- system volume snapshots;
- arbitrary launchd database files;
- unverified kernel text;
- code-signing policy outside the minimum existing Dopamine path;
- user documents, photos, keychains, or application containers.

### 3.3 Transaction rules

Every filesystem mutation belongs to a transaction with:

- transaction UUID;
- expected source hash;
- destination path;
- pre-existing object metadata;
- temporary staging path;
- checksum after write;
- commit marker;
- rollback action;
- final verification result.

No transaction may be considered committed until all files are present, permissions are correct, hashes match, and a final manifest has been atomically renamed into place.

### 3.4 Kill switches

The app must expose and honor:

- analysis-only mode;
- disable kernel writes;
- disable bootstrap writes;
- disable launchd activation;
- force safe mode on next userspace reboot;
- force revert Paleramine environment;
- export diagnostics without attempting a jailbreak.

The defaults for research builds are analysis-only and bootstrap dry-run.

---

## 4. High-level architecture

Paleramine is divided into six trust layers.

### Layer 1: Entry provider

Obtains temporary kernel access while iOS is already running.

Initial provider:

- DarkSword observation/stability path.

Future providers may be added behind the same interface if DarkSword cannot be made reliable.

### Layer 2: Kernel session

Normalizes the entry provider's primitives into a constrained session:

- read kernel memory;
- write only through a gated writer;
- obtain kernel slide;
- identify live kernel UUID;
- report primitive limits and alignment requirements;
- revoke/close session cleanly.

### Layer 3: LiveKPF analyzer

Parses the exact kernelcache and produces symbolic findings. Initially it is fully read-only.

### Layer 4: Patch-plan verifier

Converts findings into an explicit plan and verifies expected live bytes before writes are permitted.

### Layer 5: Bootstrap transaction engine

Stages a separate rootless environment in Preboot and manages install, update, repair, and revert.

### Layer 6: Activation and loader

Uses existing Dopamine mechanisms wherever possible to activate hooks, start services, userspace reboot, enter safe mode, and expose recovery controls.

---

## 5. Repository and branch strategy

### 5.1 Branches

- `main`: current product/integration branch; no experimental Paleramine writes.
- `research/ipad5-16.7.11-support-lab`: DarkSword control and observation work.
- `research/paleramine-no-pc`: Paleramine architecture and read-only prototypes.
- Future `research/paleramine-live-write`: created only after read-only decision gates pass.

### 5.2 Source pinning

Every build must pin exact upstream commits for:

- Dopamine;
- palera1n;
- PongoOS/KPF;
- jbinit;
- palera1n loader;
- Procursus/binpack inputs;
- ElleKit or any substitute hook framework;
- ChOma/XPF/libjailbreak submodules.

No workflow may build from an unrecorded moving branch without first writing the resolved commit SHA to the build manifest.

### 5.3 Licensing

Current relevant licensing observed:

- Dopamine: MIT.
- palera1n: MIT.
- PongoOS: MIT.
- palera1n loader: MIT.
- jbinit/plooshInit: MIT plus LGPL-3.0-only portions.

The build must preserve notices, identify LGPL-covered files, publish corresponding source for distributed LGPL components, and avoid copying code whose license is unclear.

---

## 6. Module design

## 6.1 `PLEntryProvider`

Purpose: isolate the kernel entry from all later stages.

Required behavior:

- report provider identifier and version;
- report exact supported device/build set;
- start an attempt with a unique attempt UUID;
- stream structured stage events;
- return a `PLKernelSession` only after primitive self-tests pass;
- return a typed failure code;
- clean all provider-owned resources on failure;
- never leave a retry thread running after cancellation.

Suggested provider states:

- idle;
- preparing;
- spraying;
- racing;
- locating PCB;
- corrupting socket;
- validating early read/write;
- locating kernel base;
- stabilizing primitives;
- complete;
- failed;
- cancelled.

No later component may call DarkSword globals directly.

## 6.2 `PLKernelSession`

Purpose: provide a single audited gateway to the live kernel.

Required metadata:

- session UUID;
- device/product/build;
- page size;
- kernel slide;
- kernel UUID;
- kernelcache SHA-256;
- provider and provider build SHA;
- minimum safe read size;
- maximum read/write size;
- alignment restrictions;
- primitive type;
- creation timestamp;
- revoked state.

Methods should be conceptually limited to:

- validated read;
- gated write;
- compare-and-write;
- read pointer with canonical-address validation;
- close/revoke.

The public API should not expose unrestricted raw kernel writes to UI code.

## 6.3 `PLKernelIdentity`

Purpose: prove that the analyzed kernelcache matches the live kernel.

Identity inputs:

- `kern.osversion`;
- device model;
- kernel Mach-O UUID;
- kernelcache file SHA-256;
- expected static base;
- live slide;
- selected immutable signature bytes read from multiple regions.

A kernel identity is valid only when all identity sources agree.

## 6.4 `PLLiveKPFAnalyzer`

Purpose: adapt useful arm64 userland KPF logic into a deterministic analyzer.

Milestone-1 behavior:

- parse only the kernelcache file;
- perform no live kernel access;
- emit symbolic findings and confidence;
- record the source rule that produced every finding;
- reject ambiguous matches;
- produce stable output for identical input.

Milestone-2 behavior:

- accept a read-only `PLKernelSession`;
- translate static addresses using the verified slide;
- compare live bytes against file bytes;
- classify findings as:
  - exact match;
  - already changed by Dopamine;
  - mismatch;
  - unreadable;
  - preboot-only;
  - unsafe after boot.

KPF code that assumes PongoOS physical mappings, pre-XNU timing, or bootloader-owned memory must not be imported into the live writer.

## 6.5 `PLPatchPlan`

Purpose: make every proposed live change reviewable and reproducible.

A plan header contains:

- schema version;
- plan UUID;
- device/build allowlist;
- kernel UUID and SHA-256;
- analyzer source SHA;
- Dopamine source SHA;
- creation timestamp;
- analysis-only/write-capable flag;
- signer identity;
- overall plan hash.

Each patch record contains:

- stable record identifier;
- symbolic purpose;
- source rule;
- target static address;
- target live address;
- length;
- expected original bytes hash;
- replacement bytes hash;
- full replacement bytes only in protected build artifacts;
- mask if instruction fields are intentionally variable;
- required predecessor records;
- live-safe classification;
- rollback bytes hash;
- verification rule;
- severity if verification fails.

A write is permitted only through compare-and-write semantics. If the expected original value does not match, the complete write phase aborts.

## 6.6 `PLPatchExecutor`

This module does not exist in the first build.

When eventually enabled, it must:

1. revalidate kernel identity immediately before writing;
2. suspend conflicting Paleramine worker activity;
3. verify all patch records before writing the first record;
4. apply the smallest independently safe group;
5. read back every modified region;
6. abort on the first mismatch;
7. restore previously changed reversible records where safe;
8. write a signed execution receipt;
9. never continue with a partially verified plan.

No patch executor may apply a patch classified as preboot-only.

## 6.7 `PLBootstrapTransaction`

Purpose: install a dedicated Paleramine rootless environment without overwriting another jailbreak.

Requirements:

- unique Preboot subdirectory;
- no hard-coded reuse of another environment's active directory;
- immutable bootstrap manifest;
- complete file hashes;
- permissions and ownership manifest;
- minimum free-space check;
- staging directory on the same APFS volume;
- atomic commit marker;
- versioned environment metadata;
- repair and uninstall modes;
- stale-transaction recovery.

Recommended states:

- absent;
- staging;
- staged;
- validating;
- committed-inactive;
- activating;
- active;
- safe-mode;
- reverting;
- corrupt/incomplete.

The first bootstrap milestone only unpacks into an app-owned test directory and verifies the manifest. Preboot writes remain disabled.

## 6.8 `PLLaunchdAdapter`

Purpose: activate only the minimum services required for the rootless environment.

First preference: reuse Dopamine's proven launchd/libjailbreak path.

Palera1n jbinit concepts may inform:

- service ordering;
- loader registration;
- safe mode state;
- recovery markers;
- userspace reboot behavior.

Do not directly transplant a preboot ramdisk `launchd` replacement into a fully booted system. Every service action must be translated into a live-safe Dopamine operation.

## 6.9 `PLLoaderController`

Purpose: provide one in-app control surface rather than installing a second untrusted loader during early research.

Required screens:

- compatibility and exact-build status;
- entry attempt and stage timeline;
- diagnostics export;
- analysis report;
- bootstrap status;
- activate jailbreak;
- safe mode;
- repair environment;
- force revert;
- licenses and source provenance.

The loader must never hide a failed verification behind a generic retry button.

## 6.10 `PLRecoveryManager`

Must operate before attempting a new jailbreak and detect:

- stale transaction directories;
- missing commit markers;
- manifest/hash mismatches;
- environment created by a different source SHA;
- duplicate active rootless roots;
- partial launchd activation;
- previous panic/CPU-watchdog marker;
- insufficient space for repair.

Recovery actions:

- export diagnostics;
- discard uncommitted staging;
- repair committed but inactive environment;
- mark safe mode;
- force revert Paleramine-owned paths;
- refuse destructive action if ownership cannot be proven.

---

## 7. Build sequence and decision gates

## Build B0: source-provenance baseline

Purpose: prove the exact official Dopamine baseline and signing pipeline.

Changes:

- no exploit behavior changes;
- unique bundle build number;
- source commit embedded in app metadata;
- UUID/dSYM manifest;
- unsigned and signed IPA hashes.

Output:

- control IPA;
- dSYM bundle;
- build manifest;
- signing/provisioning manifest with secrets excluded.

Gate B0 passes when the installed app's binary UUID and build manifest match CI outputs.

## Build B1: stock DarkSword observation build

Purpose: identify the exact failing stage while preserving race timing and search geometry.

Do not add sleeps to the inner race handshake.

Instrumentation points:

1. exploit initialization;
2. device/build/page-size detection;
3. target-file creation;
4. physical contiguous mapping creation;
5. pass start;
6. allocation summary;
7. socket spray start/end;
8. mapping start/end;
9. every 512 or 1024 pages scanned;
10. delta in `successReadCount` per progress interval;
11. highest successful race index;
12. PCB marker found;
13. PCB candidate rejection reason;
14. corruption loop start/success;
15. early read/write self-test;
16. kernel base search start/end;
17. primitive publication;
18. patchfinding start/end;
19. bootstrap start/end;
20. userspace reboot request.

Performance rules:

- use a fixed-size in-memory ring buffer;
- avoid filesystem writes in the inner page/race loop;
- flush at stage boundaries or every several seconds;
- do not log kernel pointers in user-visible UI;
- preserve a private diagnostic export for development;
- measure the logging overhead against B0.

Counters:

- pass number;
- mapping index;
- pages scanned;
- successful race reads;
- race failures;
- PCB candidates;
- rejection categories;
- corruption attempts;
- socket count;
- live file descriptors;
- Mach port count if available;
- retained IOSurface count;
- resident/physical footprint;
- elapsed wall time;
- process CPU time.

Gate B1 passes when one device attempt can be classified without relying only on a system CPU report.

## Build B2: cleanup validation build

Purpose: test resource lifetime without changing exploit placement geometry.

Candidate changes, one at a time:

1. release each retained search-mapping IOSurface before deallocating its VM mapping;
2. record dictionary count before and after cleanup;
3. verify ports and sockets return near baseline after a failed pass;
4. preserve inner race timing;
5. add delay only between complete failed passes, not inside the race.

This build must not combine cleanup fixes with lower socket counts or reduced search coverage. Otherwise results cannot identify the cause.

Gate B2 passes when repeated failed passes do not show monotonic memory or retained-object growth.

## Build B3: bounded search experiment

Purpose: avoid the CPU diagnostic window while measuring reliability.

Profiles must be separate builds or remotely selected signed configurations:

- stock: 8 x 128 MB mappings;
- bounded-4: maximum 4 x 128 MB mappings per pass;
- 512 MB/128 MB: 4 mappings;
- 512 MB/64 MB: 8 mappings;
- reduced socket spray profile.

Only one parameter changes per experiment.

A pass should stop at a conservative wall-clock threshold before the observed 149-second report duration, clean all resources, return control to the app, and require an explicit retry or controlled automatic retry with a rest interval.

Gate B3 passes when a profile avoids CPU diagnostics and has a measurable non-zero success rate.

## Build B4: kernel-session read-only build

Purpose: wrap successful DarkSword output in `PLKernelSession`.

Required self-tests:

- canonical pointer checks;
- static/live kernel identity agreement;
- repeated reads of immutable regions;
- page-boundary read tests;
- primitive revocation test;
- no write API exposed.

Gate B4 passes after repeated sessions return identical identity data and close cleanly.

## Build K0: offline KPF adapter

Purpose: compile selected userland KPF logic for arm64 and analyze the exact 20H360 kernelcache in CI.

Rules:

- no on-device kernel access;
- no patch writes;
- deterministic JSON output;
- every finding includes rule provenance and confidence;
- duplicate/ambiguous findings fail the build;
- compare output against Dopamine XPF/libjailbreak findings.

Gate K0 passes when repeated CI runs produce byte-identical findings for the same kernelcache.

## Build K1: LiveKPF comparison build

Purpose: compare offline findings to live kernel memory through a read-only session.

Output classifications:

- exact live match;
- expected relocation/slide match;
- already modified by existing Dopamine initialization;
- mismatch;
- inaccessible;
- preboot-only;
- unsafe after boot.

No writes.

Gate K1 passes when all proposed live-safe findings are exact and no unexplained mismatch remains.

## Build P0: signed patch-plan build

Purpose: generate and verify a plan without executing it.

The app displays:

- kernel identity;
- plan hash;
- record count;
- live-safe record count;
- rejected/preboot-only count;
- mismatch count;
- source SHAs.

Gate P0 passes only with zero unexplained mismatch.

## Build F0: bootstrap dry-run

Purpose: validate palera1n-compatible bootstrap contents without writing Preboot.

Actions:

- download or embed pinned bootstrap assets;
- verify signatures/hashes;
- unpack to an app-controlled staging directory;
- verify permissions manifest conceptually;
- calculate required disk space;
- generate transaction manifest;
- delete staging cleanly.

Gate F0 passes when unpack/verify/revert succeeds repeatedly.

## Build F1: inactive Preboot transaction

Purpose: stage a Paleramine-owned rootless environment without activating it.

Actions:

- acquire necessary privileges through existing Dopamine mechanisms;
- create unique staging path;
- copy and verify files;
- atomically commit environment manifest;
- do not modify launchd activation state;
- reboot normally and verify stock boot;
- reopen app and verify environment ownership/integrity;
- force revert the inactive environment.

Gate F1 passes after install/reboot/verify/revert cycles leave no orphaned paths.

## Build A0: activation dry-run

Purpose: resolve required services and hooks without launching them.

Output:

- exact service plan;
- dependency order;
- existing Dopamine equivalent for each action;
- rollback action;
- safe-mode behavior.

Gate A0 passes when every action has an existing live-safe mechanism or is rejected.

## Build A1: minimal activation

Purpose: activate the smallest environment required to prove userspace jailbreak state.

Do not start package managers or tweak injection initially.

Success proof:

- rootless prefix resolves;
- a Paleramine-owned service starts;
- trust/codesign path works for one controlled binary;
- service stops cleanly;
- userspace reboot returns to a known state.

## Build A2: loader and safe mode

Add:

- package-manager bootstrap;
- tweak injection only after base environment is stable;
- safe mode;
- exit safe mode;
- repair;
- force revert;
- complete license/source screen.

## Release candidate

A release candidate requires all acceptance tests in Section 12 and no unresolved critical risk.

---

## 8. CI/CD plan

### 8.1 Workflow outputs

Every workflow run must retain:

- resolved dependency SHAs;
- complete source manifest;
- compiler and SDK versions;
- build command/environment flags;
- unsigned IPA;
- signed IPA hash;
- main app dSYM;
- DarkSword framework dSYM;
- all custom framework dSYMs;
- Mach-O UUID map;
- kernelcache hash/UUID used by KPF analysis;
- KPF findings JSON;
- patch-plan JSON and signature;
- bootstrap manifest and hashes;
- installer URL and source proof;
- redacted signing report;
- test report.

Artifacts used for crash symbolication should remain available longer than temporary installer tunnels.

### 8.2 Reproducibility

The workflow must fail if:

- a dependency resolves to a different SHA than the manifest;
- generated patch findings change without an explicit review update;
- dSYM UUID does not match the packaged binary;
- signed IPA changes the executable UUID unexpectedly;
- kernelcache identity is absent;
- a write-capable build is produced without an exact build allowlist.

### 8.3 Separate channels

- `control`: stock behavior.
- `observe`: read-only instrumentation.
- `cleanup`: resource-lifetime experiment.
- `bounded`: parameter experiment.
- `analysis`: LiveKPF read-only.
- `filesystem-dry-run`.
- `preboot-inactive`.
- `activation-lab`.

The app title and bundle build metadata must visibly identify the channel.

---

## 9. Diagnostics design

### 9.1 Structured event record

Each event should include:

- monotonic timestamp;
- attempt UUID;
- session UUID if available;
- stage identifier;
- event identifier;
- severity;
- mapping/pass counters where applicable;
- memory and CPU snapshot where applicable;
- source build SHA;
- binary UUID;
- typed result code.

### 9.2 Privacy

Default exports should redact:

- full UDID;
- signing secrets;
- developer certificate private data;
- user paths unrelated to Paleramine;
- kernel pointers in logs intended for public sharing.

Private development exports may include addresses only when explicitly enabled and should be clearly labeled.

### 9.3 Symbolication

The export bundle should contain a manifest mapping every binary UUID to:

- repository SHA;
- artifact name;
- dSYM UUID;
- load address if known;
- architecture;
- build timestamp.

This prevents future reports from showing only anonymous offsets.

---

## 10. Test matrix

### 10.1 Entry testing

For each entry profile:

- 10 warm attempts;
- 10 attempts after app force-quit;
- 10 attempts after normal reboot;
- test at high and moderate battery;
- test with Wi-Fi on/off where kernelcache acquisition is already cached;
- test with low but safe free storage;
- record thermal state;
- record background apps where practical.

Metrics:

- success rate;
- median and worst runtime;
- mapping where success occurs;
- peak footprint;
- CPU time;
- cleanup residuals;
- app close, panic, or CPU diagnostic.

### 10.2 Kernel analysis testing

- deterministic output across repeated CI runs;
- same kernelcache on separate machines;
- corrupted kernelcache must fail;
- wrong build must fail;
- one-byte modified test fixture must produce mismatch;
- duplicate finder result must fail closed;
- live identity mismatch must fail closed.

### 10.3 Filesystem testing

- interrupted during download;
- interrupted during unpack;
- interrupted before commit marker;
- interrupted after commit marker;
- insufficient disk space;
- malformed manifest;
- wrong ownership/permissions;
- pre-existing unrelated directory;
- normal reboot after inactive commit;
- complete force revert.

### 10.4 Activation testing

- service start failure;
- service crash loop;
- userspace reboot failure;
- safe-mode marker;
- package-manager omitted;
- tweak injection disabled;
- duplicate environment detection;
- force revert from active and inactive states.

---

## 11. Risk register

### R1. DarkSword entry never reaches stable kernel read/write

Severity: critical to viability.

Mitigation:

- Build B stage isolation;
- cleanup validation;
- controlled geometry experiments;
- provider abstraction for replacement entry.

Stop condition: no measurable success after controlled profiles and no new entry candidate.

### R2. Instrumentation changes exploit timing

Severity: high.

Mitigation:

- ring buffer;
- sparse progress events;
- compare B0 and B1 timing;
- no inner-loop file writes;
- no sleeps in race handshake.

### R3. Live patch plan targets wrong build or bytes

Severity: critical.

Mitigation:

- exact build allowlist;
- kernel UUID/hash verification;
- compare-and-write;
- full preflight verification;
- read-only milestones first.

### R4. Preboot transaction damages another jailbreak environment

Severity: critical.

Mitigation:

- unique namespace;
- ownership manifest;
- never delete unknown paths;
- inactive staging first;
- force-revert limited to owned paths.

### R5. launchd activation creates a userspace boot loop

Severity: critical.

Mitigation:

- minimal service set;
- dry-run dependency plan;
- safe-mode marker;
- one service at a time;
- rollback before userspace reboot;
- normal cold reboot returns stock.

### R6. Resource leak triggers jetsam or CPU diagnostics

Severity: high.

Mitigation:

- retained-object counters;
- cleanup assertions;
- bounded passes;
- inter-pass rest;
- peak-memory acceptance limit.

### R7. Binary/dSYM mismatch makes reports unusable

Severity: high.

Mitigation:

- CI UUID validation;
- source proof embedded in app;
- long-lived symbol artifacts.

### R8. Licensing violation

Severity: high.

Mitigation:

- component inventory;
- preserve notices;
- corresponding source for LGPL portions;
- no unknown-license code.

### R9. Signing/provisioning changes behavior

Severity: medium.

Mitigation:

- identical signing pipeline across control/experiment;
- entitlement diff artifact;
- embedded provisioning profile report;
- do not confuse signing fixes with exploit fixes.

### R10. User assumes successful installation means successful support

Severity: medium.

Mitigation:

- display exact stage and build channel;
- separate `installed`, `entry succeeded`, `analysis passed`, `bootstrap committed`, and `active` states.

---

## 12. Acceptance criteria

Paleramine is not considered supported until all of the following pass.

### Entry

- at least 8 successful cold-reboot attempts out of 10 on the exact target;
- no monotonic memory growth across failed retries;
- no CPU diagnostic during the test series;
- no kernel panic during the acceptance series;
- controlled failure returns to usable UI.

### Kernel identity and analysis

- exact live/file UUID agreement;
- deterministic analyzer output;
- zero unexplained mismatches;
- all live-safe records independently reviewed;
- no write-capable code enabled by default.

### Bootstrap

- three complete inactive install/reboot/revert cycles;
- no modification outside owned paths;
- manifest and hashes survive reboot;
- interrupted transactions recover correctly.

### Activation

- minimal service activation succeeds repeatedly;
- userspace reboot succeeds repeatedly;
- safe mode works;
- force revert works;
- normal reboot returns the device to stock execution state.

### Product quality

- every shipped binary has matching symbols;
- diagnostics export is complete and privacy-redacted;
- license notices and corresponding source obligations are satisfied;
- source and artifact hashes are visible in the app.

---

## 13. Immediate implementation backlog

### Priority 1: Build B observation channel

1. Revert timing-changing sleeps from the observation variant.
2. Preserve stock DarkSword geometry.
3. Implement fixed-size ring-buffer logger.
4. Add pass/mapping/page/race/PCB/memory counters.
5. Embed source SHA and UUID manifest.
6. Retain dSYMs and symbol map.
7. Publish a separately named installer.

### Priority 2: cleanup experiment

1. Add retained IOSurface count assertions.
2. Release search-mapping IOSurfaces before VM deallocation in the cleanup-only channel.
3. Verify port/socket cleanup.
4. Compare footprint curves against stock observation.

### Priority 3: read-only Paleramine skeleton

1. Add `Paleramine/` module directory.
2. Implement compatibility gate.
3. Define `PLEntryProvider` and `PLKernelSession` interfaces.
4. Add diagnostics export schema.
5. Add read-only mode UI.

### Priority 4: offline LiveKPF

1. Pin PongoOS source commit.
2. Inventory KPF dependencies.
3. Separate pure parser/finder code from Pongo runtime code.
4. Compile arm64 userland analyzer in CI.
5. Analyze exact 20H360 kernelcache.
6. Compare findings with XPF/libjailbreak.
7. Emit deterministic JSON.

### Priority 5: bootstrap dry-run

1. Pin palera1n loader, jbinit, and binpack inputs.
2. Produce license/component manifest.
3. Define Paleramine bootstrap manifest.
4. Unpack and verify in app container.
5. Implement transaction simulator and rollback tests.

No live kernel patching or Preboot activation should start before Priorities 1-5 produce evidence that their gates pass.

---

## 14. Final engineering position

The feasible invention is not palera1n running checkm8 on itself. It is a hybrid in which:

- Dopamine supplies the post-boot entry and live primitives;
- userland KPF contributes analysis logic where it is compatible;
- Dopamine remains the authority for live-safe kernel and userspace operations;
- palera1n contributes bootstrap, loader, safe-mode, and recovery design concepts;
- every dangerous action is build- and byte-verified;
- the environment remains semi-untethered and reverts to stock after a full reboot.

The project remains viable only if Build B proves or produces a reliable in-iOS entry. Therefore the correct next executable deliverable is the stock-behavior observation build, not a write-capable KPF or bootstrap build.
