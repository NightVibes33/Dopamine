# A15 SecureROM Differential Research Plan

Target: `iPhone14,6` / D49AP / A15 (`t8110`)

## Why this is the next original-research path

Public A15 SecureROM revisions are cataloged (`iBoot-6338.0.0.200.15` A0 and `iBoot-6338.0.0.200.19` B0/B1), while the public `usbliter8` root cause is understood on A12/A13. That gives us a concrete static-analysis program: compare A13 and A15 SecureROM behavior and look for new candidate bug classes instead of trying to force-port the known A12/A13 exploit.

## Research surfaces to diff

| Surface | Question | Output |
|---|---|---|
| USB/DFU request handling | What parser/state-machine behavior changed between A13 and A15? | Function/region delta map |
| DART setup | How is USB DMA isolation established on A15 versus A13? | Initialization delta summary |
| Allocator/tasking | Did object layout, task stacks, or allocation discipline materially change? | Heap/tasking delta summary |
| Image4/manifest parsing | Are there input-validation changes in immutable boot code? | Parser delta candidates |
| Error/recovery paths | Are there integer/state transitions reachable before signed hand-off? | Candidate state-machine edges |
| Production/development gating | Which branches differ by fuse/configuration state? | Gate inventory |
| A0 versus B0/B1 A15 ROM | What changed inside the same SoC generation? | Intra-A15 security-fix candidates |

## Highest-value comparison order

1. **A15 A0 → A15 B0/B1**: same architecture, smallest semantic distance; changes are strong candidates for manufacturing/security fixes.
2. **A13 → A15 A0**: identifies the generation jump that made `usbliter8` ineffective and exposes unrelated new code paths.
3. **A14 → A15**: separates the A14 DART hardening transition from A15-specific changes.

## Candidate acceptance rules

A static difference becomes a research candidate only when it has all of:

- an externally reachable input or hardware-driven state transition;
- a plausible memory-safety, arithmetic, lifetime, state-machine, or validation invariant;
- retail A15 relevance (not prototype/JTAG-only);
- evidence that the code executes before the normal signed boot hand-off;
- a reproducible static or non-destructive observation.

This repository will not turn those candidates into an operational SecureROM exploit chain. It will preserve enough evidence to decide whether a candidate is real and whether it could satisfy `A15-PRIMITIVE-REQUIREMENTS.md`.

## Current facts driving the plan

- Public research says the known DWC2 underflow route is blocked on A14+ because SecureROM configures DART correctly.
- Therefore the useful question is not “how do we replay `usbliter8`?” but “what *other* pre-iBoot attack surfaces remain in T8110 SecureROM?”
- Public A15 ROM catalogs expose multiple A15 revisions, making intra-generation differential analysis possible.

## Deliverables

- binary-diff metadata tool (`romdiff.py`);
- candidate scoring/intake tool (`candidate-score.py`);
- JSON candidate records under `data/candidates/`;
- an A15 A0↔B0/B1 change log once actual ROM images are supplied to the offline tooling;
- a ranked static candidate list with explicit evidence and uncertainty.
