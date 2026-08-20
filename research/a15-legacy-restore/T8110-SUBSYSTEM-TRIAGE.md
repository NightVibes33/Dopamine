# T8110 SecureROM Subsystem Triage

This note records the first segment-aware, anonymized subsystem classification of the cleaned A15 A0 → B0/B1 SecureROM residual delta set. It is static reverse-engineering triage only.

## Validated pipeline

GitHub Actions run `32405205908` completed successfully and produced artifact `9420000989`, digest `sha256:352c16a6f036c7d2cbefcafb9ddfe7d81252ff1562ac455b62001d03ba3c9984`.

The run performed:

- pinned T8110 A0 and B0/B1 ROM verification;
- structural ROM diff;
- segment-accurate Ibis layout recovery;
- ARM64 instruction-class comparison;
- de-duplicated heuristic function fingerprinting;
- changed-function feature triage;
- executable-segment classification;
- anonymized subsystem archetype classification.

Raw ROM binaries were removed before artifact upload.

## Segment result

Ibis identifies the changed-function candidates as executable-code changes:

- total residual triage candidates: **26**;
- candidates mapped to executable `TEXT`: **26**;
- non-`TEXT` candidates: **0**.

This removes one source of false positives: the current residual set is not explained by changed CONST/DATA/BSS bytes alone.

## Archetype result

| Static archetype | Candidate count |
|---|---:|
| small/helper/layout-like | 11 |
| parser/state-machine-like | 9 |
| memory-transform-like | 5 |
| call-orchestration-like | 1 |
| system-control-like | 0 |

Evidence-strength distribution:

- `MEDIUM`: **2**
- `LOW_MEDIUM`: **1**
- `LOW`: **23**

Every entry remains `vulnerability_status=NOT_ESTABLISHED`.

## Highest-priority anonymized candidates

### CAND-001

- archetype: `parser_state_machine_like`
- structural score: **259**
- evidence strength: `MEDIUM`
- source class: nearby unmatched A0/B0-B1 pair
- major static delta: +62 decoded instructions, +12 comparisons, +8 conditional branches, +16 arithmetic operations, +4 loads, +4 stores, while direct calls decrease by 3.

Interpretation: this is the clearest control/validation-state expansion in the current two-revision corpus. It is the first target for deeper *static* subsystem identification, but the delta alone does not establish a bug or security impact.

### CAND-002

- archetype: `memory_transform_like`
- structural score: **100**
- evidence strength: `MEDIUM`
- mnemonic similarity: **0.803**
- the B0/B1 form is 24 decoded instructions smaller with reductions in load/control-flow/call activity.

### CAND-003

- archetype: `call_orchestration_like`
- structural score: **78**
- evidence strength: `LOW_MEDIUM`
- present as an A0-only heuristic function candidate in the current matching model.

## Important limitation

The pinned public corpus contains two T8110 revisions (`6338.0.0.200.15` and `6338.0.0.200.19`). That is enough for stepping differential analysis but not enough for a strong within-A15 persistence test.

The next static validation step is therefore **neighboring-SoC context**: compare A15 candidate fingerprints against A14/t8103 and A16/t8120 ROM families to distinguish inherited boot-ROM architecture from A15 stepping-specific changes. Cross-SoC differences will be treated as context only, never as proof of vulnerability.

## Current conclusion

The research has narrowed ~35k changed aligned words to **26 executable-code candidates**, with one dominant parser/state-machine-like delta. No SecureROM vulnerability or exploit has been established yet.
