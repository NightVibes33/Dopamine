#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JAILBREAKER = ROOT / "Application" / "Dopamine" / "Jailbreak" / "DOJailbreaker.m"
IDENTITY = ROOT / "Application" / "Dopamine" / "Paleramine" / "PLBuildIdentity.h"
MANIFEST = ROOT / "paleramine-build-manifest.txt"

for path in (JAILBREAKER, IDENTITY, MANIFEST):
    if not path.exists():
        raise SystemExit(f"Run paleramine_full_build_patch.py first; missing {path.relative_to(ROOT)}")

identity = IDENTITY.read_text(encoding="utf-8")
old_stage = '#define PL_BUILD_STAGE @"Entry + Runtime Integration"'
new_stage = '#define PL_BUILD_STAGE @"Runtime Preview • Kernel Entry Disabled"'
if identity.count(old_stage) != 1:
    raise SystemExit("Could not locate Paleramine build-stage marker")
IDENTITY.write_text(identity.replace(old_stage, new_stage), encoding="utf-8")

source = JAILBREAKER.read_text(encoding="utf-8")
anchor = '    [[DOUIManager sharedInstance] sendLog:PLBuildSubtitle() debug:NO];\n'
preview_gate = anchor + '''    *errOut = [NSError errorWithDomain:@"PaleramineRuntimePreview"
                                      code:1001
                                  userInfo:@{NSLocalizedDescriptionKey:
                                      @"Paleramine Runtime Preview is installed correctly. Kernel entry is intentionally disabled in this build, so it cannot jailbreak or run DarkSword."}];
    *showLogs = NO;
    return;
'''
if source.count(anchor) != 1:
    raise SystemExit("Could not locate Paleramine runtime-entry anchor")
JAILBREAKER.write_text(source.replace(anchor, preview_gate), encoding="utf-8")

with MANIFEST.open("a", encoding="utf-8") as handle:
    handle.write("build_mode=runtime-preview\n")
    handle.write("kernel_entry=disabled\n")
    handle.write("ota_installable=true\n")

print("Applied safe Paleramine Runtime Preview gate")
