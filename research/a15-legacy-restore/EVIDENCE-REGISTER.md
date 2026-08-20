# A15 Legacy-Restore Evidence Register

This register separates observations from conclusions so an unverified assumption does not become a compatibility claim.

| ID | Claim | Evidence class | Status |
|---|---|---|---|
| E-001 | `iPhone14,6` is the SE 3 product identifier | Public device metadata | CONFIRMED |
| E-002 | `19E241` is iOS 15.4 | Public IPSW/build metadata | CONFIRMED |
| E-003 | `19E241` supports product `iPhone14,6` | Actual Apple `BuildManifest.plist` | CONFIRMED |
| E-004 | The manifest contains D49AP / CPID `0x8110` / BDID `0x10` identities | Actual Apple `BuildManifest.plist` | CONFIRMED |
| E-005 | The manifest contains both erase and update IPSW identities | Actual Apple `BuildManifest.plist` | CONFIRMED |
| E-006 | Each matching identity contains 80 restore components | Actual Apple `BuildManifest.plist` | CONFIRMED |
| E-007 | A13 `surrealra1n` support exists | Public project documentation/source | CONFIRMED |
| E-008 | `surrealra1n` documents A15 support | Public project documentation/source | NOT FOUND |
| E-009 | Public `usbliter8` SecureROM research targets A12/A13, including SE 2/A13, not SE 3/A15 | Public device/support lists and independent writeups | CONFIRMED |
| E-010 | Public A15 TXM/SPTM patch-analysis exists, including SE 3 references | Public research source | CONFIRMED |
| E-011 | That A15 TXM/SPTM work supplies an A15 SecureROM/DFU primitive | Public research source | NOT ESTABLISHED |
| E-012 | A15 SEP compatibility with the proposed legacy environment is established | Independent technical evidence | NOT ESTABLISHED |
| E-013 | A restore-authorization bypass for this A15 target is established | Security-sensitive capability | NOT ESTABLISHED |
| E-014 | A social-media disclosure attributed to `ncxcq/apex`, with PoC credit to `rooootdev`, claims 14 SPTM vulnerabilities leading to a successful jailbreak across A12-A17 on iOS 26.0-26.5 (possibly 26.6) | Social post / secondary public reporting; no independently verified public PoC located yet | UNVERIFIED / HIGH-IMPACT |
| E-015 | If E-014 becomes reproducible on retail A15, it would materially improve current-OS jailbreak feasibility for an SE 3 on a supported iOS 26 build | Architectural consequence of a real SPTM bypass | CONDITIONAL |
| E-016 | A retail A15 SPTM jailbreak by itself supplies SecureROM/DFU control, SEP downgrade compatibility, or unsigned-IPSW restore authorization | Boot-chain separation / restore requirements | NOT ESTABLISHED |

## Verified real-manifest run

GitHub Actions run `32402473440` completed successfully. It range-fetched the Apple-hosted IPSW ZIP metadata and `BuildManifest.plist`, ran syntax checks and unit tests, verified both D49AP hardware identities, generated the structured report and component matrix, and uploaded artifact `9418990839` (`iPhone14-6-19E241-manifest-analysis`).

Artifact digest:

`sha256:941ca6f70e6e376eab34eb2a5df0143ea1d8f43a681ce054f4aa7444c4c12a88`

The generated manifest summary is committed at `data/19E241/manifest-summary.json`.

## New SPTM disclosure watch — 2026-08-20

A new public claim says reverse engineering of SPTM produced 14 vulnerabilities and a successful jailbreak with an A12-A17 / iOS 26.0-26.5 support claim, with iOS 26.6 described as probable. The linked X post is currently treated as a lead, not proof. The project should promote E-014 to `CONFIRMED` only after at least one of the following appears publicly:

- reproducible source or PoC with a retail-device support matrix;
- independent retail-device reproduction;
- a detailed technical write-up whose claimed primitive can be mapped to real SPTM/TXM behavior;
- integration into a maintained jailbreak project with reproducible device results.

This matters to the current-OS jailbreak side because public Dopamine 3 material already distinguishes simulator/Corellium support for SPTM-era systems from real-device support on newer versions where an SPTM bypass is missing. A genuine retail A15 bypass would therefore fill a meaningful current gap.

It does not, by itself, resolve the legacy-restore blocker: unsigned iOS 15.4 restore still depends on control earlier in the boot/restore authorization path plus SEP/firmware compatibility.

## Decision rule

Only `CONFIRMED` claims should be treated as established facts. `UNVERIFIED`, `CONDITIONAL`, `NOT FOUND`, and `NOT ESTABLISHED` are research states rather than proof of theoretical impossibility.

## Current assessment

The BuildManifest question is resolved: `19E241` is unquestionably packaged for `iPhone14,6` / D49AP and includes the expected production DFU, boot-chain, SEP, kernel, baseband, and restore-environment components.

The new SPTM jailbreak claim is potentially the most important current-OS A15 development in this project, but until a reproducible retail PoC or independent verification appears it remains unverified. Even if confirmed, SPTM control is downstream of SecureROM/DFU and does not automatically grant an unsigned downgrade path.
