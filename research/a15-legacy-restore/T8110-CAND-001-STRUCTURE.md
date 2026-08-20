# T8110 CAND-001 Aggregate Static Structure

## Scope

This report records the redacted aggregate CFG/data-flow characterization produced by `cand001-static-structure.py` for the pinned A15/T8110 A0 and B0/B1 SecureROM revisions.

The analysis is static and non-operational. It does not emit function offsets, branch/call targets, instruction operands, crafted DFU input, trigger sequences, patches, or exploit steps.

## Validation

Latest validated head: `c40a9ce57f9e2f3e18cac25f117dd9291780b465`

- `A15 CAND-001 Static Structure` run `32410272841` — `success`
  - Artifact `9421844499`
  - Digest `sha256:be17f69c56710918275db3e4f6b5230e3be529e63c8d7e59fd18c67d097c9100`
- `A15 Legacy Restore Analysis` run `32410272708` — `success`
  - Artifact `9421857118`
  - Digest `sha256:e6f23771bf5d5a7d602701fb2619afa1c4d223468b91d674f251db558a151299`

The structure workflow re-fetches and verifies the pinned public T8110 ROM revisions, reconstructs the changed-function set, characterizes `CAND-001`, verifies report redaction, removes the ROM binaries, and uploads only the aggregate JSON report.

## Aggregate CFG result

| Metric | A15 A0 | A15 B0/B1 | Delta |
|---|---:|---:|---:|
| Decoded instructions | 27 | 89 | +62 |
| Estimated basic blocks | 7 | 17 | +10 |
| Internal direct branch targets | 2 | 4 | +2 |
| Estimated back edges | 0 | 2 | +2 |
| Compare→guard pairs | 3 | 13 | +10 |
| Max compare→branch distance | 1 | 2 | +1 |
| Conditional branches | 4 | 12 | +8 |
| Unconditional branches | 1 | 2 | +1 |
| Direct calls | 4 | 1 | -3 |

The B0/B1 implementation therefore has substantially more internal control-flow structure while relying on fewer direct helper calls.

## Aggregate data-flow / operation mix

| Metric | A15 A0 | A15 B0/B1 | Delta |
|---|---:|---:|---:|
| Compares | 3 | 15 | +12 |
| Arithmetic operations | 1 | 17 | +16 |
| Loads | 3 | 7 | +4 |
| Stores | 3 | 7 | +4 |
| Moves | 3 | 10 | +7 |
| Conditional selects | 0 | 1 | +1 |
| Logical/bit operations | 0 | 1 | +1 |

Selected normalized densities:

| Density | A15 A0 | A15 B0/B1 |
|---|---:|---:|
| Compare | 0.1111 | 0.1685 |
| Conditional branch | 0.1481 | 0.1348 |
| Guard logic | 0.2593 | 0.3034 |
| Arithmetic | 0.0370 | 0.1910 |
| Direct/indirect call | 0.1481 | 0.0112 |
| Memory access | 0.2222 | 0.1573 |

## Broad role classification

Both revisions independently classify as:

`guarded_state_or_validation_logic`

The important change is therefore not a broad role swap. It is a large increase in internal validation/state complexity inside the same broad role:

- basic-block estimate increases from 7 to 17;
- compare→guard coupling increases from 3 to 13 pairs;
- two backward internal edges appear in the B0/B1 static CFG estimate;
- arithmetic density rises sharply;
- direct-call density collapses from 0.1481 to 0.0112.

Under the current static model, this is consistent with a formerly compact DFU-associated validation/state routine being substantially rewritten into a more self-contained state/validation implementation on B0/B1.

## Security interpretation

This strengthens the statement that `CAND-001` is a meaningful stepping-specific DFU-associated rewrite rather than a trivial layout or helper-call change.

It does **not** establish why Apple changed the routine. In particular, this result does not establish:

- attacker-controlled input reaches a newly added guard;
- a vulnerability exists in A0;
- B0/B1 is a security fix;
- memory corruption or authentication bypass;
- code execution or a retail A15 early-boot primitive;
- an unsigned restore or downgrade path.

**Vulnerability status:** `NOT_ESTABLISHED`

**Security-fix status:** `NOT_ESTABLISHED`

## Next static milestone

The next defensible step is to compare the aggregate state/validation shape against the corresponding A14 and A16 DFU-associated homologs and determine which parts of the B0/B1 complexity are uniquely T8110 stepping-specific versus shared with later-generation validation architecture.
