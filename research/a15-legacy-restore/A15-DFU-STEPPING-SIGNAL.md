# A15 DFU Stepping-Specific Static Signal

This report consolidates the current strongest static result from the T8110 SecureROM A0 → B0/B1 analysis. It records revision/lineage evidence only; it does not establish a vulnerability or describe an exploit path.

## Validation run

- Analysis head: `6d341a41b7538196a54222175b41478eab29cd97`
- Workflow run: `32406575262` — **success**
- Artifact: `9420500556`
- Artifact digest: `sha256:29cafaca74941ef4228ccb4ef5ce51271f49061fd75676e1ddc575f141209ff7`

## CAND-001 revision-side context

CAND-001 is the highest-ranked `usb_dfu` / `parser_state_machine_like` revision candidate associated on the A15 A0 side with the printable descriptor `Apple Mobile Device (DFU Mode)`.

| Candidate side | Instructions | Best A14/T8101 similarity | Best A16/T8120 similarity | Interpretation |
|---|---:|---:|---:|---|
| A15 A0 | 27 | **1.0000** (27 insns) | **0.9310** (31 insns) | strong cross-generation homolog family |
| A15 B0/B1 | 89 | **0.5029** (86 insns) | **0.5854** (75 insns) | **no clear neighboring-generation homolog** |

This is materially stronger than the earlier generic cross-SoC result because the A0 and B0/B1 sides are evaluated independently rather than using only the A0 representative.

## Descriptor lineage context

The descriptor-specific lineage already established:

- A14 B1 27/25-instruction descriptor routines → A15 A0 27/25-instruction routines: **1.0000** mnemonic similarity.
- A14/A15-A0 27/25-instruction family → A16 A0 31/29-instruction family: approximately **0.9310 / 0.9259** similarity.
- A15 B0/B1 does not expose the descriptor through the same 27/25-style routine family under the same static-reference heuristic.

The A15 B0/B1 89-instruction side is therefore not explained by the normal A14 → A15 → A16 descriptor-routine lineage recovered by this project.

## Call-neighborhood result

A separate static direct-call analysis found:

- A14 B1's common 3-instruction descriptor helper has one direct caller.
- A15 A0's equivalent helper has one direct caller.
- A15 B0/B1's equivalent 3-instruction helper has **no direct caller** under the same heuristic function model.
- A16 A0's small descriptor helper also has no recovered direct caller, while larger descriptor-bearing functions exist separately.

This rules out the simplest model where A15 B0/B1 merely moves the old descriptor reference behind an otherwise unchanged direct helper call. The descriptor-reference/call topology itself changed.

## Current classification

**A15 B0/B1 DFU-PATH STEPPING-SPECIFIC STRUCTURAL OUTLIER — HIGH STATIC REVIEW PRIORITY.**

Evidence supporting that classification:

1. same-SoC A0 → B0/B1 revision change;
2. executable `TEXT` location;
3. strongest function-level structural score in the T8110 revision diff;
4. A0 side statically associated with DFU;
5. exact A14 B1 → A15 A0 lineage;
6. strong A14/A15-A0 → A16 lineage;
7. B0/B1 89-instruction side has no clear A14 or A16 homolog;
8. descriptor-helper call topology changes in B0/B1.

## What this does not establish

The signal could still represent:

- stepping-specific hardware support;
- production diagnostics/configuration changes;
- compiler/refactoring or inlining effects;
- functional bug correction;
- defensive hardening;
- a security-relevant correction.

No current static evidence distinguishes these explanations conclusively, and vulnerability status remains `NOT_ESTABLISHED`.

## Next static discriminator

The next useful non-operational pass is to compare the **data/reference and direct-callee archetypes** of the A15 A0 27-instruction side versus the B0/B1 89-instruction side, while keeping results aggregate/anonymized. The goal is to determine whether the rewrite added validation/state checks, platform/stepping setup, or an unrelated responsibility without producing crafted DFU inputs or executable payloads.
