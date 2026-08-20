# T8110 CAND-001 Static Evidence Dossier

## Scope

This document consolidates the strongest non-operational static evidence for `CAND-001` from the pinned public SecureROM comparison pipeline on the A15/T8110 research branch.

It does **not** establish a vulnerability, exploitability, an early-boot primitive, a signing bypass, SEP compromise, or a working downgrade path.

## Validation baseline

Latest validated workflow:

- Workflow: `A15 Legacy Restore Analysis`
- Run: `32406989966`
- Result: `success`
- Head: `b0dc997689bfbc387d1f8ab5e6e7e247a64c51eb`
- Artifact: `9420652029`
- Artifact digest: `sha256:55f7e17d09b0ef59bf49350c69aad6b73040775f1bea3db3bff1e0e3759278af`

The workflow verifies pinned ROM sources before analysis and removes ROM binaries before artifact upload.

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

> `CAND-001` is a high-priority A15-stepping-specific, DFU-associated static review candidate whose B0/B1 implementation is materially more complex than the A0 form and is not explained by the current simple inlining heuristic.

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

The appropriate next research milestone is additional static validation of the candidate's broad control-flow/data-flow role and revision history without constructing a crafted trigger or exploit chain.
