#!/usr/bin/env python3
"""Offline, evidence-gated matcher for the 14 unresolved CVEs."""
import argparse, hashlib, json, subprocess
from pathlib import Path

ROWS = [
 ("CVE-2026-43813","CloudAttestation",["enforceEnvironment","ComputeNodeValidator","CloudAttestation.environment"],"function","function-level public anchor; public research says this is PCC policy handling, not a general app-signing bypass"),
 ("CVE-2026-43805","IOKit",[],"none","no public IOKit class or method"),
 ("CVE-2026-64749","Kernel",[],"none","no public subsystem, function, or crash signature"),
 ("CVE-2026-43778","Kernel",[],"none","no public freed object type or function"),
 ("CVE-2026-43724","Kernel",[],"none","input-sanitization fix class only; no public input or sink"),
 ("CVE-2026-64751","Kernel",[],"none","no public freed object type or function"),
 ("CVE-2026-43776","AppleDouble",["AppleDouble"],"component","component only; no public parser function"),
 ("CVE-2026-43811","Books",["Books"],"component","component only; no public raced path"),
 ("CVE-2026-64709","Kernel",[],"none","no public disclosure source or function"),
 ("CVE-2026-43739","Kernel",[],"none","bounds-checking fix class only; no public function"),
 ("CVE-2026-43816","Kernel",[],"none","no public subsystem or function"),
 ("CVE-2026-43814","Kernel",[],"none","no public freed object type or function"),
 ("CVE-2026-64729","Kernel",[],"none","no public freed object type or function"),
 ("CVE-2026-64747","AVEVideoEncoder",["AVEVideoEncoder"],"component","component only; no public function connecting it to LFS"),
]
ALL_NEEDLES=sorted({needle for _,_,needles,_,_ in ROWS for needle in needles})

def scan_file(p):
 h=hashlib.sha256()
 found=set()
 tails={needle:b"" for needle in ALL_NEEDLES}
 encoded={needle:needle.encode() for needle in ALL_NEEDLES}
 with p.open("rb") as f:
  for block in iter(lambda:f.read(1048576),b""):
   h.update(block)
   for needle, raw in encoded.items():
    data=tails[needle]+block
    if raw in data: found.add(needle)
    tails[needle]=data[-max(len(raw)-1,0):] if len(raw)>1 else b""
 return h.hexdigest(),found

def corpus(root):
 out={}
 for p in sorted(x for x in root.rglob("*") if x.is_file()):
  digest,string_hits=scan_file(p)
  path=str(p.relative_to(root))
  relevant=string_hits or any(n.lower() in path.lower() for n in ALL_NEEDLES)
  symbols=set()
  if relevant:
   try:
    result=subprocess.run(["nm","-gj",str(p)],check=False,capture_output=True,text=True,errors="replace",timeout=60)
    symbols={n for n in ALL_NEEDLES if n in result.stdout}
   except subprocess.TimeoutExpired:
    symbols=set()
  out[path]={"string_hits":string_hits,"symbol_hits":symbols,"sha256":digest}
 return out

def sha(p):
 return scan_file(p)[0]

def hits(corpus_data, needles):
 path_hits=sorted({needle for path in corpus_data for needle in needles if needle.lower() in path.lower()})
 string_hits=sorted({needle for data in corpus_data.values() for needle in needles if needle in data["string_hits"]})
 symbol_hits=sorted({needle for data in corpus_data.values() for needle in needles if needle in data["symbol_hits"]})
 return path_hits,string_hits,symbol_hits

def changed_files(beta3, fixed):
 b={Path(path).name:data["sha256"] for path,data in beta3.items()}
 f={Path(path).name:data["sha256"] for path,data in fixed.items()}
 return sorted(name for name in b.keys() & f.keys() if b[name] != f[name])

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
 changed=changed_files(bc,fc)
 rows=[]
 for cve,component,needles,anchor_level,note in ROWS:
  bp,bs,by=hits(bc,needles); fp,fs,fy=hits(fc,needles)
  component_changed=sorted(name for name in changed if component.lower() in name.lower())
  if anchor_level == "none":
   disposition="deferred-no-public-code-anchor"; gap="public class/function/object/crash signature or patch hunk"
  elif anchor_level == "component":
   if bp or bs or by or fp or fs or fy:
    disposition="component-observed-unvalidated"; gap="function-level public anchor"
   else:
    disposition="component-only-unmatched"; gap="function-level public anchor"
  elif bs or by or fs or fy:
   disposition="public-anchor-signature-observed"; gap="prove vulnerable beta-3 and patched comparator control flow"
  elif bp or fp:
   disposition="component-path-observed"; gap="content/symbol-level patch anchor"
  else:
   disposition="function-anchor-unmatched"; gap="extract or locate the anchored function in both builds"
  rows.append({"cve":cve,"component":component,"public_needles":needles,"public_anchor_level":anchor_level,"public_note":note,
   "beta3_path_hits":bp,"fixed_path_hits":fp,
   "beta3_string_hits":bs,"fixed_string_hits":fs,
   "beta3_symbol_hits":by,"fixed_symbol_hits":fy,
   "component_files_changed":component_changed,
   "disposition":disposition,"proof_gap":gap})
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
