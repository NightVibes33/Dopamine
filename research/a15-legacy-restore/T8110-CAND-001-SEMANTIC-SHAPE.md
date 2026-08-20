# T8110 CAND-001 Semantic-Shape Analysis

## Scope

This report records the redacted semantic-shape classification of `CAND-001` across pinned A14, A15 A0, A15 B0/B1, and A16 SecureROM context.

The analysis is static and non-operational. It does not emit function offsets, branch/call targets, instruction operands, constants, USB request values, crafted DFU input, trigger sequences, patches, or exploit instructions.

## Validation

- Workflow: `A15 CAND-001 Semantic Shape`
- Run: `32416830061`
- Result: `success`
- Head: `dbeff7c732a66eabf27e72a5678018db3d94812d`
- Artifact: `9424204297`
- Artifact digest: `sha256:b57c038bce43ff43cc337457796d2014e546d4cf40d7e262cb340f6996a32cb3`

Full A15 analysis on the same head:

- Run: `32416830076`
- Result: `success`
- Artifact: `9424218244`
- Artifact digest: `sha256:3713448c5e1a35e900301943c0892b26556e693e62fefceea522edafb21a5df7`

## Semantic-shape result

| Revision context | Instructions | Total guard sites | Guard clusters | Max cluster | Nested-guard pressure | Back-edge estimate | Direct calls | Semantic shape |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| A14 | 27 | 4 | 2 | 3 | 2 | 0 | 4 | `compact_guarded_validation` |
| A15 A0 | 27 | 4 | 2 | 3 | 2 | 0 | 4 | `compact_guarded_validation` |
| A15 B0/B1 | 89 | 13 | 5 | 3 | 6 | 2 | 1 | `dense_multi_guard_state_validation` |
| A16 | 31 | 4 | 2 | 3 | 2 | 0 | 4 | `compact_guarded_validation` |

The A15 B0/B1 form therefore adds **9 aggregate guard sites** relative to A15 A0 and also **9 guard sites** relative to the maximum observed in the A14/A16 neighboring homolog context.

The pipeline sets:

`b0_b1_unique_dense_guard_shape = true`

## Guard-family composition

| Revision context | Flag-compare guards | Bit-test guards | Zero-test guards |
|---|---:|---:|---:|
| A14 | 3 | 1 | 0 |
| A15 A0 | 3 | 1 | 0 |
| A15 B0/B1 | 13 | 0 | 0 |
| A16 | 3 | 1 | 0 |

The neighboring compact family preserves the same broad mix: three flag-compare guard motifs plus one bit-test guard motif. The B0/B1 form instead presents thirteen flag-compare guard motifs under the current mnemonic-shape heuristic.

## Coarse data-flow context around guards

| Revision context | Arithmetic-before-guard | Load-before-guard | Store-after-guard |
|---|---:|---:|---:|
| A14 | 0 | 1 | 1 |
| A15 A0 | 0 | 1 | 1 |
| A15 B0/B1 | 3 | 1 | 4 |
| A16 | 0 | 1 | 1 |

This indicates that the B0/B1 expansion is not merely more branches. Under the current static model it also contains more arithmetic feeding guard decisions and more stores immediately following guard sites, while the compact A14/A15-A0/A16 family remains aligned.

## Interpretation

The strongest defensible static statement is now:

> The A14 → A15 A0 → A16 DFU-associated homolog family retains a compact guarded-validation shape, while A15 B0/B1 uniquely expands into a dense, internally controlled multi-guard state/validation shape.

This further strengthens the interpretation that the rewrite is **T8110 stepping-specific** rather than ordinary cross-generation code evolution.

It does **not** establish why Apple changed the routine.

The evidence does not establish:

- attacker-controlled input reaching any specific guard;
- a vulnerability in A15 A0;
- that A15 B0/B1 is a security fix;
- memory corruption;
- authentication bypass;
- code execution;
- a retail A15 early-boot primitive;
- an unsigned restore or downgrade path.

**Vulnerability status:** `NOT_ESTABLISHED`

**Security-fix status:** `NOT_ESTABLISHED`

## Current research conclusion

`CAND-001` remains the strongest static candidate in the current T8110 corpus. The evidence now converges across independent dimensions:

- stepping-specific function-size expansion;
- cross-generation mnemonic ancestry;
- aggregate CFG divergence;
- guard-density expansion;
- guard-cluster expansion;
- added iterative/control-state structure;
- failure of simple helper inlining to explain the change.

That is sufficient to justify continued non-operational semantic analysis, but not to claim a vulnerability or construct a trigger/exploit path.
