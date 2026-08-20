# T8110 CAND-001 Static Evidence Dossier

## Scope

This document consolidates the strongest non-operational static evidence for `CAND-001` from the pinned public SecureROM comparison pipeline on the A15/T8110 research branch.

It does **not** establish a vulnerability, exploitability, an early-boot primitive, a signing bypass, SEP compromise, or a working downgrade path.

## Validation baseline

Latest validated workflows on head `dad91c56d64bb6791205d5b45724dc42ed4490c1`:

- `A15 Legacy Restore Analysis` run `32410131468` — `success`
  - Artifact `9421809404`
  - Digest `sha256:213b4fa2271a510d8e92be40adf8c94e41fa8898ed9b62fc76fc6c675eabf953`
- `A15 CAND-001 Static Structure` run `32410131503` — `success`
  - Artifact `9421794169`
  - Digest `sha256:506aacf8369bc3b73cac5ef2c314f2ecf9c639aee9bd45cfe54168353e30a0d6`

The workflows verify pinned ROM sources before analysis and remove ROM binaries before artifact upload.

## Candidate classification

| Field | Result |
|---|---|
| Candidate | `CAND-001` |
| Source kind | `nearby_unmatched_pair` |
| Archetype | `parser_state_machine_like` |
| Static subsystem tag | `usb_dfu` |
| Static label | `Apple Mobile Device (DFU Mode)` |
| Structural score | `259` |
| Evidence strength | `MEDIUM` |
| Research priority | `HIGH_STATIC_REVIEW_PRIORITY` |
| Vulnerability status | `NOT_ESTABLISHED` |

The current hypothesis scope is **DFU-associated control/validation-state logic**. This is a static classification only.

## A15 revision delta

The heuristic function analysis pairs the A15 A0 and B0/B1 sides as the same high-priority changed region.

| Static feature | A15 A0 | A15 B0/B1 | Delta |
|---|---:|---:|---:|
| Decoded instructions | 27 | 89 | +62 |
| Arithmetic | 1 | 17 | +16 |
| Compare | 3 | 15 | +12 |
| Conditional branches | 4 | 12 | +8 |
| Control-flow operations | 10 | 16 | +6 |
| Direct calls | 4 | 1 | -3 |
| Loads | 3 | 7 | +4 |
| Stores | 3 | 7 | +4 |

The B0/B1 side is therefore substantially larger and more branch/compare/arithmetic-heavy while making fewer direct calls.

## Aggregate CFG/data-flow characterization

The dedicated static-structure workflow reconstructs `CAND-001` from the pinned ROMs and emits only aggregate structural metrics.

| CFG metric | A15 A0 | A15 B0/B1 | Delta |
|---|---:|---:|---:|
| Estimated basic blocks | 7 | 17 | +10 |
| Internal direct branch targets | 2 | 4 | +2 |
| Estimated back edges | 0 | 2 | +2 |
| Compare→guard pairs | 3 | 13 | +10 |
| Max compare→branch distance | 1 | 2 | +1 |

Normalized densities:

| Density | A15 A0 | A15 B0/B1 |
|---|---:|---:|
| Compare | 0.1111 | 0.1685 |
| Conditional branch | 0.1481 | 0.1348 |
| Guard logic | 0.2593 | 0.3034 |
| Arithmetic | 0.0370 | 0.1910 |
| Call | 0.1481 | 0.0112 |
| Memory access | 0.2222 | 0.1573 |

Both revisions independently classify as `guarded_state_or_validation_logic`.

The important signal is therefore **not** a broad role change. The B0/B1 implementation preserves the same broad validation/state role while becoming much more internally structured: ten additional estimated basic blocks, ten additional compare→guard pairs, two estimated backward edges, sharply higher arithmetic density, and substantially lower direct-call density.

This is consistent with a compact DFU-associated validation/state routine being rewritten into a more self-contained state/validation implementation. It does not establish why the rewrite occurred or whether it fixed a security flaw.

## DFU association

The read-only string-reference pass finds a direct static reference from the A0 form of `CAND-001` to:

`Apple Mobile Device (DFU Mode)`

Only a small minority of the residual candidates receive printable labels, and `CAND-001` is the candidate assigned the `usb_dfu` subsystem tag.

This associates the candidate with DFU-related code, but the reference alone does not establish what security property the function enforces.

## Neighboring-generation context

The A0 form has strong mnemonic-shape homologs in neighboring generations:

| Comparison | Best similarity | Classification |
|---|---:|---|
| A15 A0 vs A14/T8101 | 1.0000 | `strong_homolog_signal` |
| A15 A0 vs A16/T8120 | 0.9310 | `strong_homolog_signal` |

The B0/B1 form does not show the same clear neighboring-generation match:

| Comparison | Best similarity | Classification |
|---|---:|---|
| A15 B0/B1 vs A14/T8101 | 0.5029 | `no_clear_homolog_signal` |
| A15 B0/B1 vs A16/T8120 | 0.5854 | `no_clear_homolog_signal` |

This makes the rewrite look **A15 stepping-specific** under the current heuristic rather than a simple generation-wide compiler/layout drift.

## Descriptor-family lineage

The independent DFU descriptor lineage pass reports:

- A14 B1 → A15 A0, 27-instruction descriptor-logic form: `1.0000` mnemonic similarity.
- A15 A0 → A16 A0 best corresponding form: `0.9310` mnemonic similarity.
- The A15 B0/B1 descriptor-family view retains the tiny descriptor helper but no longer exposes the same 27/25-instruction descriptor-logic forms under the current heuristic.

The direct-call neighborhood also changes between the A15 A0 and B0/B1 views.

Again, this is lineage/topology evidence, not proof of a security fix.

## Refactor / inlining check

A separate mnemonic-window check was used to test whether the 89-instruction B0/B1 form could be explained by obvious inlining of A0 callees.

Results:

- A0 caller: 27 instructions, 4 decoded direct-call targets.
- B0/B1 caller: 89 instructions, 1 decoded direct-call target.
- Best A0 callee sequence similarity found inside the B0/B1 caller: `0.4286`.
- Tool disposition: `NO_CLEAR_STATIC_INLINING_SIGNAL`.

Therefore, simple helper inlining does **not** currently explain the rewrite.

## What the evidence supports

The evidence supports the following research statement:

> `CAND-001` is a high-priority A15-stepping-specific, DFU-associated static review candidate whose B0/B1 implementation is materially more complex than the A0 form, preserves a broad guarded state/validation role, and is not explained by the current simple inlining heuristic.

## What the evidence does not support

The current data does **not** establish:

- a memory-safety bug;
- an authentication-state bypass;
- attacker-controlled input reaching the changed logic;
- a crash or corruption primitive;
- code execution;
- persistence;
- a retail A15 SecureROM exploit;
- an unsigned restore path;
- SEP compatibility for the proposed iPhone14,6 downgrade.

## Research status

**Classification:** `HIGH-PRIORITY A15-STEPPING-SPECIFIC DFU STATIC REVIEW CANDIDATE`

**Vulnerability status:** `NOT_ESTABLISHED`

The next defensible static milestone is cross-generation structural comparison of this guarded state/validation shape against the corresponding A14 and A16 DFU-associated homologs, while continuing to avoid crafted trigger or exploit construction.
