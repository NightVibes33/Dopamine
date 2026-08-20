# iPhone14,6 / 19E241 Component Matrix

This is the interpretation layer for the output of `component-matrix.py`.

| Component class | Why it matters | Evidence currently available | Compatibility conclusion |
|---|---|---|---|
| iBoot / iBEC / iBSS / LLB | Boot-chain execution | 19E241 public component inventory | UNKNOWN |
| SEP firmware | Secure Enclave state and restore compatibility | 19E241 public component inventory | UNKNOWN |
| Restore ramdisk | Restore environment | 19E241 public component inventory | UNKNOWN |
| Restore kernel/cache | Restore execution environment | 19E241 public component inventory | UNKNOWN |
| DeviceTree | Hardware description | 19E241 public component inventory | UNKNOWN |
| Baseband | Cellular firmware | 19E241 public component inventory | UNKNOWN |
| Cryptex/runtime firmware | Runtime system components | 19E241 public component inventory | UNKNOWN |

## Important distinction

The presence of a component in a BuildManifest establishes that Apple packaged that component for the target product/build. It does **not** establish that a currently installed device will accept the component, that SEP state is compatible, or that the resulting system will boot.

## Required evidence for a stronger conclusion

- Exact component metadata from the target BuildManifest.
- Independent evidence for A15/19E241 SEP compatibility.
- Independent evidence for the relevant A15 boot-chain behavior.
- A documented restore authorization path, if one exists.

Until those are established, every compatibility cell remains `UNKNOWN` rather than being inferred from filenames or from A13 behavior.
