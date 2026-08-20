# T8110 CAND-001 Semantic-Shape Analysis

## Scope

This report records the redacted semantic-shape classification of `CAND-001` across pinned A14, A15 A0, A15 B0/B1, and A16 SecureROM context.

The analysis is static and non-operational. It does not emit function offsets, branch/call targets, instruction operands, constants, USB request values, crafted DFU input, trigger sequences, patches, or exploit instructions.

## Corrected validation

Current corrected analysis head used for the measurements below: `8a711c0b3b26fbf9c3fdac12cf7b00f3ab78c008`.

Semantic-shape workflow:

- Run: `32417617118`
- Result: `success`
- Artifact: `9424478545`
- Artifact digest: `sha256:dc5327ce955d5c263b97892e798bfc7f01a41cdc49a92a78e7632ea2dac7ba5f`

Full A15 analysis on the same head:

- Run: `32417617154`
- Result: `success`
- Artifact: `9424492178`
- Artifact digest: `sha256:d77d99ff09b3e062503ef11a33c7fbc986357bd974bd7448036f2f3b113f5916`

## Measurement correction

The original report treated compare→guard pairings as though they were distinct guard branches. Multiple comparisons can feed the same conditional branch, so the corrected analyzer reports both metrics separately.

| Revision | Distinct guard branches | Compare→guard pairings |
|---|---:|---:|
| A14 | 4 | 3 |
| A15 A0 | 4 | 3 |
| A15 B0/B1 | **11** | **13** |
| A16 | 4 | 3 |

The B0/B1 implementation therefore adds **7 distinct guard branches** relative to A15 A0 and neighboring context, while the compare→guard-pair metric expands by **10**.

## Semantic-shape result

| Revision context | Instructions | Unique guards | Guard clusters | Max cluster | Nested-guard pressure | Back-edge estimate | Direct calls | Semantic shape |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| A14 | 27 | 4 | 2 | 3 | 2 | 0 | 4 | `compact_guarded_validation` |
| A15 A0 | 27 | 4 | 2 | 3 | 2 | 0 | 4 | `compact_guarded_validation` |
| A15 B0/B1 | 89 | **11** | **5** | 3 | **6** | **2** | **1** | `dense_multi_guard_state_validation` |
| A16 | 31 | 4 | 2 | 3 | 2 | 0 | 4 | `compact_guarded_validation` |

The pipeline still sets:

`b0_b1_unique_dense_guard_shape = true`

## Guard-family composition

| Revision context | Flag-compare pairings | Unique flag-guard branches | Bit-test guard branches | Zero-test guard branches |
|---|---:|---:|---:|---:|
| A14 | 3 | 3 | 1 | 0 |
| A15 A0 | 3 | 3 | 1 | 0 |
| A15 B0/B1 | **13** | **11** | 0 | 0 |
| A16 | 3 | 3 | 1 | 0 |

The compact A14/A15-A0/A16 family preserves the same broad shape. B0/B1 instead presents eleven distinct flag-guard branches participating in thirteen compare→guard pairings.

## Coarse data-flow context around unique guards

| Revision context | Arithmetic-before-guard | Load-before-guard | Store-after-guard |
|---|---:|---:|---:|
| A14 | 0 | 1 | 1 |
| A15 A0 | 0 | 1 | 1 |
| A15 B0/B1 | **3** | 1 | **3** |
| A16 | 0 | 1 | 1 |

This indicates that the B0/B1 expansion is not merely more conditional branches. Under the corrected distinct-guard model it also contains more arithmetic feeding guard decisions and more stores immediately following guard sites, while the compact neighboring family remains aligned.

## Interpretation

The strongest defensible static statement remains:

> The A14 → A15 A0 → A16 DFU-associated homolog family retains a compact guarded-validation shape, while A15 B0/B1 uniquely expands into a dense, internally controlled multi-guard state/validation shape.

This strengthens the interpretation that the rewrite is **T8110 stepping-specific** rather than ordinary cross-generation code evolution.

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

`CAND-001` remains the strongest static candidate in the current T8110 corpus. The corrected evidence converges across independent dimensions:

- stepping-specific function-size expansion;
- cross-generation mnemonic ancestry;
- aggregate CFG divergence;
- **11 distinct B0/B1 guard branches versus 4 in neighboring context**;
- **13 compare→guard pairings versus 3**;
- guard-cluster expansion;
- added iterative/control-state structure;
- failure of simple helper inlining to explain the change.

The companion `T8110-CAND-001-GUARD-PROVENANCE.md` further classifies the added guards at a coarse, redacted semantic level.
