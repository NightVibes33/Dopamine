#!/usr/bin/env python3
"""Build an evidence-gated CVE triage ledger from exact-firmware inventories."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

SEEDS = [
    ("IOS27-CVE-64747", "CVE-2026-64747", "AVEVideoEncoder", "buffer overflow; kernel code execution", "AVEVideoEncoder", ["CWE-120"], "Apple advisory names exact component and size-validation fix"),
    ("IOS27-CVE-43813", "CVE-2026-43813", "CloudAttestation", "code-signing enforcement bypass", "CloudAttestation", ["CWE-347"], "Apple advisory names exact component"),
    ("IOS27-CVE-43723", "CVE-2026-43723", "MediaRemote", "root privilege via path handling", "MediaRemote", ["CWE-22"], "public minimal PoC and technical note exist"),
    ("IOS27-CVE-43811", "CVE-2026-43811", "Books", "modify protected filesystem via race", "Books", ["CWE-362"], "Apple advisory names exact component"),
    ("IOS27-CVE-64740", "CVE-2026-64740", "GameCenter", "sandbox escape via directory-path parsing", "GameCenter", ["CWE-22"], "Apple advisory names exact component and path-validation fix"),
    ("IOS27-CVE-28973", "CVE-2026-28973", "libc", "sandbox escape via integer overflow", "libsystem_c", ["CWE-190"], "Apple advisory names libc but no function"),
    ("IOS27-CVE-43821", "CVE-2026-43821", "WebKit", "read files outside app sandbox", "WebKit", ["CWE-200"], "public WebKit Bugzilla anchor 314867"),
    ("IOS27-CVE-43805", "CVE-2026-43805", "IOKit", "race; possible kernel-memory write", None, ["CWE-362"], "advisory only; vulnerable IOKit class is not public"),
    ("IOS27-CVE-64749", "CVE-2026-64749", "Kernel", "app-triggerable kernel-memory corruption", None, [], "advisory only; vulnerable subsystem/function is not public"),
    ("IOS27-CVE-43778", "CVE-2026-43778", "Kernel", "use-after-free; kernel-memory corruption", None, ["CWE-416"], "advisory only; vulnerable subsystem/function is not public"),
    ("IOS27-CVE-43724", "CVE-2026-43724", "Kernel", "app-triggerable kernel-memory write", None, [], "advisory only; vulnerable subsystem/function is not public"),
    ("IOS27-CVE-64751", "CVE-2026-64751", "Kernel", "use-after-free; kernel-memory write", None, ["CWE-416"], "advisory only; vulnerable subsystem/function is not public"),
]

def load(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict): raise SystemExit(f"{path}: expected JSON object")
    return value

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest()

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--b3-inventory",type=Path,required=True)
    ap.add_argument("--patched-inventory",type=Path,required=True)
    ap.add_argument("--out-json",type=Path,required=True)
    ap.add_argument("--out-md",type=Path,required=True)
    ns=ap.parse_args(); b3,patched=load(ns.b3_inventory),load(ns.patched_inventory)
    for label,obj in (("beta3",b3),("patched-side",patched)):
        for key in ("build","device","kernel_sha256","paths","strings"):
            if key not in obj: raise SystemExit(f"{label}: missing {key}")
    if b3["device"]!="iPhone17,3" or b3["build"]!="24A5380h": raise SystemExit("beta3 inventory is not the authorized exact target")
    rows=[]
    for cid,cve,component,primitive,anchor,cwe,detail in SEEDS:
        needles={component.lower()}
        if anchor: needles.add(anchor.lower())
        def hits(obj): return sorted(x for x in obj["paths"]+obj["strings"] if any(n in x.lower() for n in needles))
        b3_hits,patched_hits=hits(b3),hits(patched)
        anchored=bool(anchor and b3_hits and patched_hits)
        rows.append({"id":cid,"cve":cve,"component":component,"primitive":primitive,"anchor":anchor,"cwe":cwe,"public_detail":detail,
          "source":"sandboxed app, web content, or crafted file per Apple advisory","sink_or_broken_control":primitive,
          "beta3_hits":b3_hits[:100],"patched_hits":patched_hits[:100],
          "disposition":"candidate-present-unvalidated" if anchored else "deferred-missing-patch-anchor",
          "validation_recommended":True,"proof_gap":"instruction-level vulnerable/fixed function mapping" if anchored else "public vulnerable class, function, crash, or patch anchor"})
    report={"schema":2,"scope":{"device":b3["device"],"build":b3["build"]},"comparison":{"build":patched["build"],"device":patched["device"]},
      "input_sha256":{"beta3_inventory":sha256(ns.b3_inventory),"patched_inventory":sha256(ns.patched_inventory)},
      "safety":{"live_service_calls":False,"trigger_generation":False,"poc_execution":False,"claim_policy":"binary change alone is not attributed to a CVE"},"candidates":rows}
    ns.out_json.parent.mkdir(parents=True,exist_ok=True); ns.out_json.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    lines=["# iPhone17,3 iOS 27 CVE triage","",f"- Exact target: `{b3['build']}`",f"- Patched-side comparator: `{patched['build']}`","- PoCs executed: no","- Live services opened: no","","| Candidate | Component | Disposition | Remaining proof gap |","|---|---|---|---|"]
    lines += [f"| {r['cve']} | {r['component']} | {r['disposition']} | {r['proof_gap']} |" for r in rows]
    lines += ["","## Interpretation","","Component/path/string evidence is discovery evidence only, not CVE attribution or proof of vulnerability.","Advisory-only rows stay deferred until a public patch, crash signature, class, function, or equivalent exact anchor exists.",""]
    ns.out_md.write_text("\n".join(lines)); return 0

if __name__=="__main__": raise SystemExit(main())
