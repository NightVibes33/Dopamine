# A15 B0/B1 DFU Rewrite — Static Refactor/Inlining Assessment

This report tests whether CAND-001's A15 A0 → B0/B1 growth can be explained by simple inlining of the old A0 direct-call targets. It is static reverse-engineering evidence only; vulnerability status remains `NOT_ESTABLISHED`.

## Reproducible run

- Analysis head: `08f722f6fdd181f8606833452de2c872efd0d872`
- Workflow run: `32406857493` — **success**
- Artifact: `9420600435`
- Artifact digest: `sha256:58a48dc9b0f5186e5d5ac11e7eda376f3b506be0f447d67515d5fb4395b5644b`

## Candidate context

CAND-001 is the highest-ranked A15 SecureROM revision candidate:

- A0 side: 27 decoded instructions, 4 direct calls.
- B0/B1 side: 89 decoded instructions, 1 direct call.
- A0 side is statically associated with `Apple Mobile Device (DFU Mode)`.
- A0 has exact/strong A14/A16 homologs; the B0/B1 89-instruction side has no clear A14/A16 homolog.

The 27 → 89 growth combined with 4 → 1 direct calls made ordinary helper inlining a plausible non-security explanation. This pass tested that explanation directly at normalized mnemonic-sequence level.

## A0 callee sequences searched inside B0/B1 caller

| A0 decoded callee | Callee size | Best mnemonic-window similarity inside 89-insn B0/B1 caller |
|---|---:|---:|
| A0-CALLEE-01 | 17 | **0.4286** |
| A0-CALLEE-02 | 82 | **0.3743** |
| A0-CALLEE-03 | 79 | **0.3214** |
| A0-CALLEE-04 | 209 | **0.1812** |

No old direct-call target produces even a `0.65` likely-inlining signal inside the revised B0/B1 body.

## Reverse check

The sole decoded B0/B1 direct-call target is 55 instructions. Its best mnemonic-window similarity inside the old 27-instruction A0 caller is only **0.3171**.

## Result

**NO CLEAR STATIC INLINING SIGNAL.**

Under this heuristic, the A15 B0/B1 89-instruction DFU-associated rewrite is not well explained by simply copying the A0 routine's former callees into the caller body.

That does not prove the rewrite is security-related. Other explanations remain possible, including:

- new stepping-specific hardware/state handling;
- a larger control/validation rewrite;
- refactoring that is more substantial than direct callee inlining;
- production diagnostics/configuration changes;
- functional bug correction;
- defensive/security hardening.

## Updated static evidence stack for CAND-001

1. Highest T8110 A0→B0/B1 structural score: **259**.
2. Both sides are executable `TEXT`.
3. A0 side references `Apple Mobile Device (DFU Mode)`.
4. A14 B1 → A15 A0 27/25-instruction descriptor routines match at **1.0000** normalized mnemonic similarity.
5. A16 A0 retains strong 31/29-instruction homologs at approximately **0.9310 / 0.9259**.
6. B0/B1 descriptor-reference topology changes.
7. B0/B1 89-instruction side has no clear neighboring-generation homolog: A14 **0.5029**, A16 **0.5854**.
8. Simple old-helper inlining is not supported: best A0-callee-in-B0 similarity only **0.4286**.

## Current classification

**HIGH-PRIORITY A15-STEPPING-SPECIFIC DFU STATIC REVIEW CANDIDATE — VULNERABILITY NOT ESTABLISHED.**

The next safe discriminator is aggregate data-reference and branch/compare-shape analysis of the 27-instruction A0 side versus the 89-instruction B0/B1 side, with special attention to whether the extra B0/B1 logic looks like added validation/state gating or platform/stepping setup. No crafted DFU requests or device execution are required for that analysis.
