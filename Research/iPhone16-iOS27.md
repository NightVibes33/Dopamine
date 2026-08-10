# iPhone 16 / iOS 27 Research Baseline

Target: iPhone 16 (A18), iOS 27 beta 3 (24A5380h).

Base: upstream Dopamine 3.0.4.

Implemented:
- A18 and A18 Pro CPU-family recognition in exploit selection.
- A18 runtime diagnostics for device, OS build, and arm64e detection.

Intentionally unchanged:
- DarkSword/ClearSword support ranges remain limited to their validated firmware ranges.
- Titan remains limited to its validated A14-A17 / iOS <= 17.3.1 range.
- No version-range widening or fake exploit support.

Research gates before a real jailbreak can execute:
1. A validated kernel read/write primitive for A18 on 24A5380h.
2. A validated SPTM bypass compatible with A18/iOS 27.
3. Downstream TXM/code-signing validation after both primitives are available.

The branch must fail closed when those primitives are absent.
