#!/usr/bin/env python3
"""Offline, evidence-gated matcher for the 14 unresolved CVEs."""
import argparse, hashlib, json, subprocess
from pathlib import Path

ROWS = [
 ("CVE-2026-43813","CloudAttestation",["enforceEnvironment","ComputeNodeValidator","CloudAttestation.environment"],"function-level public anchor; public research says this is PCC policy handling, not a general app-signing bypass"),
 ("CVE-2026-43805","IOKit",[],"no public IOKit class or method"),
 ("CVE-2026-64749","Kernel",[],"no public subsystem, function, or crash signature"),
 ("CVE-2026-43778","Kernel",[],"no public freed object type or function"),
 ("CVE-2026-43724","Kernel",[],"input-sanitization fix class only; no public input or sink"),
 ("CVE-2026-64751","Kernel",[],"no public freed object type or function"),
 ("CVE-2026-43776","AppleDouble",["AppleDouble"],"component only; no public parser function"),
 ("CVE-2026-43811","Books",["Books"],"component only; no public raced path"),
 ("CVE-2026-64709","Kernel",[],"no public disclosure source or function"),
 ("CVE-2026-43739","Kernel",[],"bounds-checking fix class only; no public function"),
 ("CVE-2026-43816","Kernel",[],"no public subsystem or function"),
 ("CVE-2026-43814","Kernel",[],"no public freed object type or function"),
 ("CVE-2026-64729","Kernel",[],"no public freed object type or function"),
 ("CVE-2026-64747","AVEVideoEncoder",["AVEVideoEncoder"],"component only; no public function connecting it to LFS"),
]

def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""): h.update(b)
 return h.hexdigest()

def corpus(root):
 out={}
 for p in sorted(x for x in root.rglob("*") if x.is_file()):
  out[str(p)]=subprocess.run(["strings","-a",str(p)],check=True,capture_output=True,text=True,errors="replace").stdout
 return out

def main():
 ap=argparse.ArgumentParser()
 ap.add_argument("--beta3-components",type=Path,required=True)
 ap.add_argument("--fixed-components",type=Path,required=True)
 ap.add_argument("--beta3-kernel",type=Path,required=True)
 ap.add_argument("--fixed-kernel",type=Path,required=True)
 ap.add_argument("--out-json",type=Path,required=True)
 ap.add_argument("--out-md",type=Path,required=True)
 n=ap.parse_args()
 for p in (n.beta3_components,n.fixed_components):
  if not p.is_dir(): raise SystemExit("missing component tree: "+str(p))
 for p in (n.beta3_kernel,n.fixed_kernel):
  if not p.is_file(): raise SystemExit("missing kernel: "+str(p))
 bc,fc=corpus(n.beta3_components),corpus(n.fixed_components)
 rows=[]
 for cve,component,needles,note in ROWS:
  bh=sorted({x for s in bc.values() for x in needles if x in s})
  fh=sorted({x for s in fc.values() for x in needles if x in s})
  if not needles:
   disposition="deferred-no-public-code-anchor"; gap="public class/function/object/crash signature or patch hunk"
  elif len(needles)>1 and (bh or fh):
   disposition="public-anchor-signature-observed"; gap="prove vulnerable beta-3 and patched comparator control flow"
  else:
   disposition="component-only-unmatched"; gap="function-level patch anchor"
  rows.append({"cve":cve,"component":component,"public_needles":needles,"public_note":note,
   "beta3_hits":bh,"fixed_hits":fh,"disposition":disposition,"proof_gap":gap})
 report={"schema":1,"scope":{"device":"iPhone17,3","build":"24A5380h"},
  "safety":{"pocs_executed":False,"trigger_generation":False,"live_service_calls":False},
  "kernel_sha256":{"beta3":sha(n.beta3_kernel),"fixed":sha(n.fixed_kernel)},"results":rows}
 n.out_json.parent.mkdir(parents=True,exist_ok=True)
 n.out_json.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
 lines=["# Remaining 14 CVE anchor matches","","- Exact target: iPhone17,3 / 24A5380h",
  "- PoCs executed: no","- Trigger values generated: no","",
  "| CVE | Result | Proof gap |","|---|---|---|"]
 lines += ["| %s | %s | %s |"%(r["cve"],r["disposition"],r["proof_gap"]) for r in rows]
 lines += ["","A component or binary-string hit is discovery evidence, not proof of a vulnerable implementation.",""]
 n.out_md.write_text("\n".join(lines))
 return 0

if __name__=="__main__": raise SystemExit(main())
