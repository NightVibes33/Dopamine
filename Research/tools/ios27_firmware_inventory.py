#!/usr/bin/env python3
"""Create a deterministic, non-sensitive inventory of extracted firmware files."""
from __future__ import annotations
import argparse, hashlib, json, subprocess
from pathlib import Path

def digest(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024), b""): h.update(block)
    return h.hexdigest()

ap=argparse.ArgumentParser()
ap.add_argument("--root",type=Path,required=True)
ap.add_argument("--kernel",type=Path,required=True)
ap.add_argument("--device",required=True)
ap.add_argument("--build",required=True)
ap.add_argument("--out",type=Path,required=True)
ns=ap.parse_args()
if not ns.kernel.is_file(): raise SystemExit("kernel missing")
paths=sorted(str(p.relative_to(ns.root)) for p in ns.root.rglob("*") if p.is_file())
raw=subprocess.run(["strings","-a",str(ns.kernel)],check=True,capture_output=True,text=True).stdout
needles=("iokit","kernel","mediaremote","userclient","use after free","race")
strings=sorted({line[:500] for line in raw.splitlines() if any(n in line.lower() for n in needles)})
obj={"schema":1,"device":ns.device,"build":ns.build,"kernel_sha256":digest(ns.kernel),"paths":paths,"strings":strings[:20000]}
ns.out.parent.mkdir(parents=True,exist_ok=True)
ns.out.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
