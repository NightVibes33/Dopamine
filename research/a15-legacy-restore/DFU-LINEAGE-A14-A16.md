# SecureROM DFU Descriptor Lineage — A14 B1 → A15 → A16 A0

This report tracks only static functions that resolve the printable SecureROM descriptor `Apple Mobile Device (DFU Mode)`. It is lineage/context evidence, not a vulnerability claim and not an exploit recipe.

## Reproducible run

- Analysis head: `6158090dfaec896c4924196767c35858b36e9f79`
- Workflow run: `32406089382` — **success**
- Artifact: `9420325634`
- Artifact digest: `sha256:1dd8d452ea1ca123dc61c176ca8b8c428846e5ed5cb05babaefe453766cba936`

The candidate-evidence merge was also corrected to consume `A14_t8101` rather than the obsolete/wrong `A14_t8103` key. CAND-001 now correctly reports `A14_similarity=1.0` and `A16_similarity=0.931`.

## Descriptor-bearing routine family

| ROM | SecureROM version | Main descriptor-bearing routine family | Relationship |
|---|---|---|---|
| A14 B1 / T8101 | `5281.0.0.100.45` | 27 + 25 instructions | baseline |
| A15 A0 / T8110 | `6338.0.0.200.15` | 27 + 25 instructions | **exact mnemonic fingerprints** vs A14 B1 |
| A15 B0/B1 / T8110 | `6338.0.0.200.19` | old 27/25 family not directly recovered as descriptor-bearing; only a 3-instruction helper remains directly associated | **intra-A15 outlier / rewrite** |
| A16 A0 / T8120 | `7195.0.0.200.29` | 31 + 29 instructions | strong homolog of old 27/25 family |

## Pairwise static similarity

### A14 B1 → A15 A0

- 27-instruction routine: **1.0000** mnemonic similarity.
- 25-instruction routine: **1.0000** mnemonic similarity.

The production A14 B1 DFU descriptor routine therefore survived unchanged at normalized mnemonic level into early A15 A0.

### A14 B1 / A15 A0 → A16 A0

Best descriptor-specific homologs:

- 27 → 31 instructions: **0.9310** similarity.
- 25 → 29 instructions: **0.9259** similarity.

A16 therefore retains a strongly recognizable descendant of the older A14/A15-A0 descriptor-bearing routine family.

### A15 B0/B1

The B0/B1 descriptor analysis does **not** recover a direct 27/25-style descriptor-bearing function. The only directly resolved descriptor-associated function in this heuristic is the common 3-instruction helper.

This does not mean the larger DFU logic disappeared. It may have been inlined, split, moved behind another helper, or changed reference style. It does establish that B0/B1 is structurally distinct from both the earlier A14/A15-A0 family and the later A16 descriptor-specific family under the same analysis method.

## Current interpretation

The large A15 A0 → B0/B1 change is **not explained by the A14 → A15 generation transition**: the old routine survives exactly into A15 A0.

The fact that A16 A0 again shows a strong 31/29-instruction homolog of the older family also means the B0/B1 form cannot currently be called a simple permanent next-generation baseline. On present evidence it is better classified as an **A15 stepping-specific DFU-path rewrite/outlier**.

Possible explanations remain broad:

- stepping-specific hardware support;
- refactoring or inlining;
- diagnostics/production changes;
- defensive hardening;
- correction of a functional or security bug.

Static lineage alone does not distinguish these possibilities.

## Highest-priority static candidate

CAND-001 remains:

- archetype: `parser_state_machine_like`;
- static subsystem: `usb_dfu`;
- label: `Apple Mobile Device (DFU Mode)`;
- A14 context similarity: **1.0**;
- A16 context similarity: **0.931**;
- structural score: **259**;
- research priority: `HIGH_STATIC_REVIEW_PRIORITY`;
- vulnerability status: `NOT_ESTABLISHED`.

## Next discriminator

Compare the static call-neighborhood of the descriptor-bearing routine family across A14 B1, A15 A0, A15 B0/B1, and A16 A0. The purpose is to determine whether A15 B0/B1 primarily **moved/inlined** the old logic or materially changed the surrounding DFU subsystem topology. Only aggregate/static graph metadata should be used; no crafted DFU inputs or device execution are required.
