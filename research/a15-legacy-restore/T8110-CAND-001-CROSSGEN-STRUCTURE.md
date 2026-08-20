# T8110 CAND-001 Cross-Generation Aggregate Structure

## Scope

This report compares the redacted aggregate CFG/data-flow shape of `CAND-001` against the strongest mnemonic-shape homologs recovered from pinned A14/T8101 and A16/T8120 SecureROM images.

The analysis is static and non-operational. It does not emit function offsets, branch/call targets, instruction operands, crafted DFU input, trigger sequences, patches, or exploit steps.

## Validation

- Workflow: `A15 CAND-001 Cross-Generation Structure`
- Run: `32415360175`
- Result: `success`
- Head: `98cf8a58776914c8a2b59916e7fb1f647afdaae2`
- Artifact: `9423684342`
- Artifact digest: `sha256:c3836e0499e8de6ae0c83853bed017cbf0d139f515acda7a99ea617e7a77484b`

Pinned neighboring context:

- A14 B1 / T8101 / `iBoot-5281.0.0.100.45`
- A15 A0 / T8110 / `iBoot-6338.0.0.200.15`
- A15 B0/B1 / T8110 / `iBoot-6338.0.0.200.19`
- A16 A0 / T8120 / `iBoot-7195.0.0.200.29`

## Homolog confidence

| Comparison | Mnemonic similarity |
|---|---:|
| A14 → A15 A0 | `1.0000` |
| A16 → A15 A0 | `0.9310` |

These values support using the selected A14/A16 functions as broad architectural context for the A15 A0 DFU-associated form. They do not establish symbol identity or security equivalence.

## Aggregate CFG comparison

| Metric | A14 | A15 A0 | A15 B0/B1 | A16 |
|---|---:|---:|---:|---:|
| Decoded instructions | 27 | 27 | 89 | 31 |
| Estimated basic blocks | 7 | 7 | 17 | 7 |
| Compare→guard pairs | 3 | 3 | 13 | 3 |
| Estimated back edges | 0 | 0 | 2 | 0 |
| Internal direct branch targets | 2 | 2 | 4 | 2 |
| Conditional branches | 4 | 4 | 12 | 4 |
| Direct calls | 4 | 4 | 1 | 4 |

Under the current aggregate CFG metric, A14 and A15 A0 are exactly aligned. A16 retains the same basic-block, guard-pair, back-edge, direct-branch-target, conditional-branch, and direct-call shape despite growing from 27 to 31 decoded instructions.

A15 B0/B1 is the outlier.

## Aggregate operation mix

| Metric | A14 | A15 A0 | A15 B0/B1 | A16 |
|---|---:|---:|---:|---:|
| Arithmetic operations | 1 | 1 | 17 | 2 |
| Compares | 3 | 3 | 15 | 3 |
| Loads | 3 | 3 | 7 | 3 |
| Stores | 3 | 3 | 7 | 3 |
| Moves | 3 | 3 | 10 | 4 |

The B0/B1 form therefore contains a large increase in arithmetic, comparison, memory access, and move activity that is absent from both neighboring-generation homologs.

## Structural-distance result

The analyzer uses a deliberately coarse address-free CFG distance across:

- estimated basic blocks;
- estimated back edges;
- compare→guard pairs;
- internal direct branch targets.

Results:

| Comparison | Aggregate CFG distance |
|---|---:|
| A15 A0 → A14 | `0` |
| A15 A0 → A16 | `0` |
| A15 B0/B1 → A14 | `24` |
| A15 B0/B1 → A16 | `24` |

The current pipeline therefore classifies:

`b0_b1_more_structurally_distinct_from_both_neighbors_than_a0 = true`

## Interpretation

The strongest defensible static statement is now:

> The compact A14 → A15 A0 → A16 DFU-associated homolog family preserves essentially the same aggregate control-flow shape, while the A15 B0/B1 stepping contains a uniquely expanded internal state/validation implementation under the current model.

This strengthens the conclusion that the B0/B1 rewrite is **T8110 stepping-specific** rather than a normal A14→A15→A16 architectural progression.

It still does **not** establish why the rewrite occurred.

Specifically, the evidence does not establish:

- attacker-controlled input reaching the additional B0/B1 guards;
- a vulnerability in A15 A0;
- that B0/B1 is a security fix;
- memory corruption;
- authentication bypass;
- code execution;
- a retail A15 early-boot primitive;
- an unsigned restore or downgrade path.

**Vulnerability status:** `NOT_ESTABLISHED`

**Security-fix status:** `NOT_ESTABLISHED`

## Research conclusion

`CAND-001` remains the strongest static research candidate in the current T8110 corpus. Cross-generation structure now provides independent evidence that the large B0/B1 validation/state expansion is unusual specifically within the A15 stepping rather than shared by the A14/A16 homolog family.

Further work should remain focused on non-operational semantic classification of the added validation/state logic unless independent evidence establishes a genuine vulnerability.
