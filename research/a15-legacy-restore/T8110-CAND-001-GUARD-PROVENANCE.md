# T8110 CAND-001 Guard-Provenance Analysis

## Scope

This report records the redacted, coarse guard-provenance classification for `CAND-001` across pinned A14, A15 A0, A15 B0/B1, and A16 SecureROM context.

The analysis is static and non-operational. It does not emit function offsets, branch/call targets, instruction operands, constants, USB request values, validated field identities, crafted DFU input, trigger sequences, patches, or exploit instructions.

## Validation

Corrected analysis head: `8a711c0b3b26fbf9c3fdac12cf7b00f3ab78c008`

Guard-provenance workflow:

- Run: `32417617161`
- Result: `success`
- Artifact: `9424480965`
- Artifact digest: `sha256:2d0891b6b2720ca4251cfbdb5f7d143d628fff3069ada4ea4a46ed6a51ca4439`

Corrected semantic-shape workflow:

- Run: `32417617118`
- Result: `success`
- Artifact: `9424478545`
- Artifact digest: `sha256:dc5327ce955d5c263b97892e798bfc7f01a41cdc49a92a78e7632ea2dac7ba5f`

Full A15 analysis:

- Run: `32417617154`
- Result: `success`
- Artifact: `9424492178`
- Artifact digest: `sha256:d77d99ff09b3e062503ef11a33c7fbc986357bd974bd7448036f2f3b113f5916`

## Measurement correction

The earlier semantic report used **compare→guard pairings** as if they were unique guard branches. Multiple compares can feed the same conditional branch, so those are not equivalent metrics.

Corrected distinction:

| Revision | Distinct guard branches | Compare→guard pairings |
|---|---:|---:|
| A14 | 4 | 3 |
| A15 A0 | 4 | 3 |
| A15 B0/B1 | **11** | **13** |
| A16 | 4 | 3 |

Therefore the B0/B1 implementation adds **7 distinct guard branches** over A15 A0 / neighboring context, while producing **10 additional compare→guard pairings**.

The qualitative classification remains `dense_multi_guard_state_validation`.

## Coarse provenance result

The classifier assigns each distinct guard branch one mutually-exclusive, deliberately broad provenance hypothesis based only on nearby mnemonic/control-flow classes.

| Coarse provenance hypothesis | A14 | A15 A0 | A15 B0/B1 | A16 |
|---|---:|---:|---:|---:|
| `simple_state_or_flag_validation_like` | 0 | 0 | **7** | 0 |
| `bookkeeping_or_error_state_like` | 1 | 1 | **2** | 1 |
| `loaded_state_validation_like` | 0 | 0 | **1** | 0 |
| `bounds_or_size_validation_like` | 1 | 1 | **1** | 1 |
| `helper_result_validation_like` | 2 | 2 | **0** | 2 |

Relative to the maximum observed in A14/A15-A0/A16, B0/B1 therefore adds:

- `+7` simple state/flag-validation-like guards;
- `+1` bookkeeping/error-state-like guard;
- `+1` loaded-state-validation-like guard.

It does **not** add an aggregate `bounds_or_size_validation_like` guard under the current classifier; that category remains `1` across all four contexts.

B0/B1 also loses the two helper-result-validation-like sites found in the compact A14/A15-A0/A16 family.

## Aggregate local context

| Context feature around distinct guards | A14 | A15 A0 | A15 B0/B1 | A16 |
|---|---:|---:|---:|---:|
| Arithmetic before guard | 1 | 1 | **5** | 1 |
| Flag-compare guard | 3 | 3 | **11** | 3 |
| Load before guard | 1 | 1 | **2** | 1 |
| Store after guard | 1 | 1 | **3** | 1 |
| Nearby helper call | 4 | 4 | **0** | 4 |

This is consistent with the previously observed direct-call collapse (`4 → 1`) and large arithmetic/control-flow expansion.

## Interpretation

The strongest defensible static interpretation is:

> The A15 B0/B1 rewrite is dominated by additional locally implemented state/flag checks and bookkeeping/state-update behavior, rather than by an observable increase in the coarse bounds/size-validation category. At the same time, helper-result-oriented validation visible in the compact neighboring homolog family largely disappears.

Under this model, the rewrite therefore looks more like **internalized state/validation machinery** than a simple addition of one bounds/length check.

That distinction is useful for research prioritization, but it does not identify the actual state variable or validated field and it does not establish security intent.

## What is not established

The evidence does not establish:

- which DFU field, state variable, or object any guard validates;
- attacker-controlled input reaching any guard;
- a missing check in A15 A0;
- a vulnerability in A15 A0;
- that B0/B1 is a security fix;
- memory corruption or an authentication bypass;
- code execution;
- a retail A15 early-boot primitive;
- an unsigned restore or downgrade path.

**Attacker reachability:** `NOT_EVALUATED`

**Validated field identity:** `NOT_EVALUATED`

**Vulnerability status:** `NOT_ESTABLISHED`

**Security-fix status:** `NOT_ESTABLISHED`

## Current research conclusion

The provenance pass narrows the broad semantic hypothesis: the stepping-specific B0/B1 expansion is primarily **state/flag validation plus bookkeeping/state-update logic**, not a clear bounds/length-hardening signature under this coarse classifier.

Further analysis should remain address-free and non-operational, focusing on whether these aggregate guard families correspond to lifecycle/state-transition bookkeeping versus generic error-state handling.
