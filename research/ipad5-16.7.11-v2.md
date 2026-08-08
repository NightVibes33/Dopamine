# iPad 5 / iPadOS 16.7.11 v2 baseline

This branch is based on Dopamine 3.0.1 and intentionally keeps the upstream DarkSword/ClearSword low-VRAM workaround unchanged.

Target: iPad 5th generation (A9), iPadOS 16.7.11.

Baseline goals:
- Verify current upstream DarkSword selection.
- Verify contiguousMapping requirement and low-VRAM workaround path are present.
- Build an unsigned IPA from current 3.0.1 before adding any custom tuning.

Do not widen exploit support ranges or add speculative low-memory patches until the upstream baseline is tested on-device.
