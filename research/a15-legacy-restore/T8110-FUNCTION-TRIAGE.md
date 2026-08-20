# T8110 A0 → B0/B1 Function-Level Static Triage

This report records the first segment-aware narrowing pass over the public A15 SecureROM revision pair. It is static reverse-engineering evidence only and does not establish a vulnerability or provide an exploit path.

## Reproducible analysis run

- Branch head analyzed: `8e37ca37f85ba3f958d9ddc4c9d363760c306d23`
- GitHub Actions run: `32405030847` — **success**
- Artifact: `9419935553`
- Artifact digest: `sha256:1f6792bcebf6d6e4e6e26a454f70741d55b959d08bcd52e024afae31ea4eda5e`
- Segment mapper: `jonpalmisc/ibis` pinned at `e22ed6354139f8dbb0a88b9de4fdb5e452d8717b`

## Segment layouts

Ibis identifies both inputs as `SecureROM/t8110si`.

| Revision | TEXT file span | TEXT size | CONST offset | CONST size | DATA offset | DATA size |
|---|---:|---:|---:|---:|---:|---:|
| A0 / `6338.0.0.200.15` | `0x00000–0x28500` | 165,120 | `0x28500` | 33,464 | `0x34000` | 1,664 |
| B0/B1 / `6338.0.0.200.19` | `0x00000–0x286c0` | 165,568 | `0x286c0` | 33,512 | `0x34000` | 1,664 |

The B0/B1 executable TEXT segment is therefore **448 bytes larger** than A0.

## Function-level narrowing

The corrected heuristic fingerprint pass found:

- A0 function candidates: **956**
- B0/B1 function candidates: **962**
- Exact mnemonic-fingerprint matches: **932**
- Similar-but-changed matches: **17**
- A0-only candidates: **7**
- B0/B1-only candidates: **13**

Feature triage produced 26 distinct ranked candidate groups after pairing nearby unmatched boundaries. **All 26 are inside executable TEXT** according to Ibis. No ranked hotspot was discarded as CONST/DATA noise.

## Highest-priority static hotspots

| Rank | A0 file offset | B0/B1 file offset | Static change signal | Priority |
|---:|---:|---:|---|---:|
| 1 | `0xC2B8` | `0xC2B8` | same-start routine grows 27 → 89 decoded instructions; +8 conditional branches, +12 compares, +16 arithmetic ops, +4 loads, +4 stores; 4 → 1 direct calls | 259 |
| 2 | `0x13DF4` | `0x14054` | 78 → 54 instructions; -5 control-flow ops, -2 conditional branches, -2 direct calls, -4 loads | 100 |
| 3 | `0x12C88` | — | 78-instruction A0-only candidate with 18 direct calls / 23 control-flow ops | 78 |
| 4 | `0x11E8C` | `0x12170` | 237 → 242 instructions; mostly stable flow, +4 arithmetic ops | 22 |
| 5 | `0x1420C` | `0x14408` | 23 → 18 instructions; one conditional branch and one direct call removed | 22 |
| 6 | — | `0xC6D4` | 22-instruction B0/B1-only candidate with 5 compares and 3 conditional branches | 22 |
| 7 | `0xD858` | `0xDAC0` | 12 → 16 instructions; +1 compare, +1 conditional branch, +2 loads | 19 |
| 8 | `0xEF0C` | `0xF1A0` | 165 → 161 instructions; one direct-call/control-flow substitution | 19 |
| 9 | — | `0xD474` | 17-instruction B0/B1-only candidate with 3 compares, 2 conditional branches, and a direct call | 17 |
| 10 | `0x11804` | `0x11AD0` | 215 → 218 instructions; +1 compare, +1 conditional branch, +2 control-flow ops | 13 |

## Strongest current anchor: `0xC2B8`

`0xC2B8` is currently the strongest revision-change anchor because:

1. it starts at the **same file offset** in both ROM revisions;
2. Ibis maps it into executable `TEXT` in both revisions;
3. its apparent routine size changes dramatically rather than merely shifting with the surrounding binary;
4. the B0/B1 side adds substantial internal comparison/branch/arithmetic structure while reducing external direct calls.

That pattern is consistent with a routine that was materially rewritten or had logic inlined during the A0 → B0/B1 revision. It is **not**, by itself, evidence of a security fix.

## Next static question

The next useful discriminator is subsystem identity. The analysis should resolve read-only string/data references from these ranked functions and classify them against broad areas such as USB/DFU, Image4/manifest validation, DART/platform setup, allocator/tasking, or error/recovery handling. This can be done without constructing inputs or executing the ROM.
