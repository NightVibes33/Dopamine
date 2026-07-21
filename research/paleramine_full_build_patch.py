#!/usr/bin/env python3
from __future__ import annotations

import plistlib
import re
import struct
import zlib
from pathlib import Path
from textwrap import dedent

ROOT = Path(__file__).resolve().parents[1]

APP_DIR = ROOT / "Application" / "Dopamine"
PROJECT = ROOT / "Application" / "Dopamine.xcodeproj" / "project.pbxproj"
APP_MAKEFILE = ROOT / "Application" / "Makefile"
ROOT_MAKEFILE = ROOT / "Makefile"
INFO = APP_DIR / "Info.plist"
MAIN_UI = APP_DIR / "UI" / "DOMainViewController.m"
JAILBREAKER = APP_DIR / "Jailbreak" / "DOJailbreaker.m"
DARKSWORD = APP_DIR / "Exploits" / "DarkSword" / "DarkSword.m"
DARKSWORD_INFO = APP_DIR / "Exploits" / "DarkSword" / "Info.plist"
ASSET_CONTENTS = APP_DIR / "Assets.xcassets" / "AppIcon.appiconset" / "Contents.json"

BRAND = "Paleramine"
BUNDLE_ID = "com.nightvibes33.paleramine.ipad5"
TARGET_VERSION = "16.7.11"
TARGET_BUILD = "20H360"
TARGET_MODELS = ("iPad6,11", "iPad6,12")


def require(path: Path) -> None:
    if not path.exists():
        raise SystemExit(f"Required source file is missing: {path.relative_to(ROOT)}")


for path in (PROJECT, APP_MAKEFILE, ROOT_MAKEFILE, INFO, MAIN_UI, JAILBREAKER, DARKSWORD, DARKSWORD_INFO):
    require(path)


def replace_exact(text: str, old: str, new: str, *, count: int | None = None, label: str) -> str:
    actual = text.count(old)
    if actual == 0:
        raise SystemExit(f"{label}: expected text was not found")
    if count is not None and actual != count:
        raise SystemExit(f"{label}: expected {count} occurrence(s), found {actual}")
    return text.replace(old, new)


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


paleramine_dir = APP_DIR / "Paleramine"
paleramine_dir.mkdir(parents=True, exist_ok=True)

build_identity = dedent(f'''
#pragma once
#import <Foundation/Foundation.h>

#define PL_BRAND_NAME @"{BRAND}"
#define PL_BUILD_CHANNEL @"iPad5 Research"
#define PL_BUILD_STAGE @"Entry + Runtime Integration"
#define PL_TARGET_VERSION @"{TARGET_VERSION}"
#define PL_TARGET_BUILD @"{TARGET_BUILD}"
#define PL_TARGET_MODELS @"iPad6,11 / iPad6,12"
#define PL_BUNDLE_IDENTIFIER @"{BUNDLE_ID}"

static inline NSString *PLBuildSubtitle(void)
{{
    return [NSString stringWithFormat:@"%@ • %@ • %@", PL_BRAND_NAME, PL_BUILD_CHANNEL, PL_BUILD_STAGE];
}}
''').lstrip()
write_text(paleramine_dir / "PLBuildIdentity.h", build_identity)

safety_gate = dedent(f'''
#pragma once

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <mach/machine.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <unistd.h>

static inline NSError *PLValidatePaleramineTarget(void)
{{
    struct utsname systemInfo;
    if (uname(&systemInfo) != 0) {{
        return [NSError errorWithDomain:@"PaleramineSafety"
                                  code:1
                              userInfo:@{{NSLocalizedDescriptionKey:@"Paleramine could not identify this device."}}];
    }}

    NSString *machine = [NSString stringWithUTF8String:systemInfo.machine ?: ""];
    NSSet<NSString *> *allowedMachines = [NSSet setWithArray:@[@"iPad6,11", @"iPad6,12"]];
    if (![allowedMachines containsObject:machine]) {{
        return [NSError errorWithDomain:@"PaleramineSafety"
                                  code:2
                              userInfo:@{{NSLocalizedDescriptionKey:
                                  [NSString stringWithFormat:@"This research build only supports iPad 5th generation (iPad6,11/iPad6,12). Detected %@.", machine]}}];
    }}

    NSString *systemVersion = UIDevice.currentDevice.systemVersion;
    if (![systemVersion isEqualToString:@"{TARGET_VERSION}"]) {{
        return [NSError errorWithDomain:@"PaleramineSafety"
                                  code:3
                              userInfo:@{{NSLocalizedDescriptionKey:
                                  [NSString stringWithFormat:@"This build is locked to iPadOS {TARGET_VERSION}. Detected %@.", systemVersion]}}];
    }}

    char buildBuffer[64] = {{0}};
    size_t buildSize = sizeof(buildBuffer);
    if (sysctlbyname("kern.osversion", buildBuffer, &buildSize, NULL, 0) != 0) {{
        return [NSError errorWithDomain:@"PaleramineSafety"
                                  code:4
                              userInfo:@{{NSLocalizedDescriptionKey:@"Paleramine could not read the Darwin build number."}}];
    }}
    NSString *build = [NSString stringWithUTF8String:buildBuffer];
    if (![build isEqualToString:@"{TARGET_BUILD}"]) {{
        return [NSError errorWithDomain:@"PaleramineSafety"
                                  code:5
                              userInfo:@{{NSLocalizedDescriptionKey:
                                  [NSString stringWithFormat:@"This build is locked to Darwin {TARGET_BUILD}. Detected %@.", build]}}];
    }}

    if ((size_t)getpagesize() != 0x4000) {{
        return [NSError errorWithDomain:@"PaleramineSafety"
                                  code:6
                              userInfo:@{{NSLocalizedDescriptionKey:
                                  [NSString stringWithFormat:@"Unexpected page size: %d.", getpagesize()]}}];
    }}

    cpu_subtype_t subtype = 0;
    size_t subtypeSize = sizeof(subtype);
    if (sysctlbyname("hw.cpusubtype", &subtype, &subtypeSize, NULL, 0) == 0) {{
        if ((subtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {{
            return [NSError errorWithDomain:@"PaleramineSafety"
                                      code:7
                                  userInfo:@{{NSLocalizedDescriptionKey:@"This build requires the arm64 A9 path, not arm64e."}}];
        }}
    }}

    return nil;
}}
''').lstrip()
write_text(paleramine_dir / "PLSafetyGate.h", safety_gate)

diagnostics = dedent(r'''
#pragma once

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static FILE *pl_diag_file = NULL;
static pthread_mutex_t pl_diag_lock = PTHREAD_MUTEX_INITIALIZER;
static struct timespec pl_diag_start = {0};

static inline double PLDiagElapsed(void)
{
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - pl_diag_start.tv_sec) +
           (double)(now.tv_nsec - pl_diag_start.tv_nsec) / 1000000000.0;
}

static inline void PLDiagOpen(const char *flavor)
{
    clock_gettime(CLOCK_MONOTONIC, &pl_diag_start);
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:documents
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];
    NSString *path = [documents stringByAppendingPathComponent:@"Paleramine-Diagnostics.log"];
    pl_diag_file = fopen(path.fileSystemRepresentation, "a");
    if (pl_diag_file) setvbuf(pl_diag_file, NULL, _IOLBF, 0);

    pthread_mutex_lock(&pl_diag_lock);
    FILE *out = pl_diag_file ?: stderr;
    fprintf(out, "\n=== PALERAMINE ATTEMPT ===\n");
    fprintf(out, "flavor=%s bundle=%s target=iPad6,11/iPad6,12 os=16.7.11 build=20H360\n",
            flavor ?: "default", NSBundle.mainBundle.bundleIdentifier.UTF8String ?: "unknown");
    fflush(out);
    pthread_mutex_unlock(&pl_diag_lock);
}

static inline void PLDiagLog(const char *stage,
                             unsigned long long pass,
                             unsigned long long mapping,
                             unsigned long long pages,
                             int raceSuccesses,
                             unsigned long long surfaceCount,
                             unsigned long long socketCount,
                             const char *detail)
{
    mach_task_basic_info_data_t info = {0};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t kr = task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                                 (task_info_t)&info, &count);
    unsigned long long resident = kr == KERN_SUCCESS ? info.resident_size : 0;
    unsigned long long virtualSize = kr == KERN_SUCCESS ? info.virtual_size : 0;

    pthread_mutex_lock(&pl_diag_lock);
    FILE *out = pl_diag_file ?: stderr;
    fprintf(out,
            "t=%.3f stage=%s pass=%llu mapping=%llu pages=%llu race_success=%d surfaces=%llu sockets=%llu resident=%llu virtual=%llu detail=%s\n",
            PLDiagElapsed(), stage ?: "unknown", pass, mapping, pages,
            raceSuccesses, surfaceCount, socketCount, resident, virtualSize,
            detail ?: "-");
    fflush(out);
    pthread_mutex_unlock(&pl_diag_lock);
}

static inline void PLDiagClose(const char *detail)
{
    PLDiagLog("complete", 0, 0, 0, 0, 0, 0, detail);
    pthread_mutex_lock(&pl_diag_lock);
    if (pl_diag_file) {
        fclose(pl_diag_file);
        pl_diag_file = NULL;
    }
    pthread_mutex_unlock(&pl_diag_lock);
}
''').lstrip()
write_text(APP_DIR / "Exploits" / "DarkSword" / "PLDiagnostics.h", diagnostics)

with INFO.open("rb") as handle:
    info = plistlib.load(handle)
info["CFBundleDisplayName"] = BRAND
info["CFBundleName"] = BRAND
info["UIFileSharingEnabled"] = True
info["LSSupportsOpeningDocumentsInPlace"] = True
info["NSPhotoLibraryUsageDescription"] = f"{BRAND} needs photo-library access only when selecting a custom boot logo."
info["PLResearchBuild"] = True
info["PLTargetBuild"] = TARGET_BUILD
info["PLTargetModels"] = list(TARGET_MODELS)
with INFO.open("wb") as handle:
    plistlib.dump(info, handle, fmt=plistlib.FMT_XML, sort_keys=False)

strings_value = re.compile(r'(^\s*"[^"]+"\s*=\s*")((?:\\.|[^"])*)(";\s*$)', re.MULTILINE)
for path in APP_DIR.rglob("Localizable.strings"):
    raw = path.read_text(encoding="utf-8")
    def replace_value(match: re.Match[str]) -> str:
        value = match.group(2).replace("Dopamine", BRAND).replace("dopamine", BRAND.lower())
        return match.group(1) + value + match.group(3)
    write_text(path, strings_value.sub(replace_value, raw))

literal_pattern = re.compile(r'(@"(?:\\.|[^"])*"|\b"(?:\\.|[^"])*")')
for path in APP_DIR.rglob("*"):
    if path.suffix not in {".m", ".h", ".mm", ".c"}:
        continue
    if path in {DARKSWORD, JAILBREAKER, MAIN_UI}:
        continue
    raw = path.read_text(encoding="utf-8", errors="ignore")
    def replace_literal(match: re.Match[str]) -> str:
        token = match.group(0)
        if "Dopamine" in token or "dopamine" in token:
            token = token.replace("Dopamine", BRAND).replace("dopamine", BRAND.lower())
        return token
    updated = literal_pattern.sub(replace_literal, raw)
    if updated != raw:
        write_text(path, updated)

project = PROJECT.read_text(encoding="utf-8")
old_bundle_block = (
    'PRODUCT_BUNDLE_IDENTIFIER = com.opa334.Dopamine;\n'
    '\t\t\t\tPRODUCT_NAME = "$(TARGET_NAME)";'
)
new_bundle_block = (
    f'PRODUCT_BUNDLE_IDENTIFIER = {BUNDLE_ID};\n'
    f'\t\t\t\tPRODUCT_NAME = {BRAND};\n'
    f'\t\t\t\tEXECUTABLE_NAME = {BRAND};\n'
    f'\t\t\t\tINFOPLIST_KEY_CFBundleDisplayName = {BRAND};\n'
    f'\t\t\t\tINFOPLIST_KEY_CFBundleName = {BRAND};'
)
project = replace_exact(project, old_bundle_block, new_bundle_block, count=2, label="app build settings")
project = replace_exact(project, "MARKETING_VERSION = 2.4.99;", "MARKETING_VERSION = 0.1.0;", count=2, label="marketing version")
project = project.replace("productName = Dopamine;", f"productName = {BRAND};", 1)
PROJECT.write_text(project, encoding="utf-8")

app_make = APP_MAKEFILE.read_text(encoding="utf-8")
app_make = app_make.replace("Dopamine.ipa", "Paleramine.ipa")
app_make = app_make.replace("Dopamine.tipa", "Paleramine.tipa")
app_make = app_make.replace("Debug-iphoneos/Dopamine.app", "Debug-iphoneos/Paleramine.app")
app_make = app_make.replace("Paleramine.app/Dopamine", "Paleramine.app/Paleramine")
app_make = app_make.replace("Payload/Dopamine.app", "Payload/Paleramine.app")
app_make = app_make.replace("@echo Ad-Hoc signing Dopamine", "@echo Ad-Hoc signing Paleramine")
write_text(APP_MAKEFILE, app_make)

root_make = ROOT_MAKEFILE.read_text(encoding="utf-8")
root_make = root_make.replace("/Dopamine.tipa", "/Paleramine.tipa")
root_make = root_make.replace("./Application/Dopamine.tipa", "./Application/Paleramine.tipa")
write_text(ROOT_MAKEFILE, root_make)

ui = MAIN_UI.read_text(encoding="utf-8")
ui = replace_exact(
    ui,
    '#import "DOLogCrashViewController.h"',
    '#import "DOLogCrashViewController.h"\n#import "../Paleramine/PLBuildIdentity.h"',
    count=1,
    label="main UI import",
)
ui = replace_exact(
    ui,
    'DOHeaderView *headerView = [[DOHeaderView alloc] initWithImage: [UIImage imageNamed:@"Dopamine"] subtitles: @[\n'
    '        [DOGlobalAppearance mainSubtitleString:[[DOEnvironmentManager sharedManager] versionSupportString]],\n'
    '        [DOGlobalAppearance secondarySubtitleString:DOLocalizedString(@"Credits_Made_By")],\n'
    '    ]];',
    'UIImage *paleramineSymbol = [UIImage systemImageNamed:@"shield.lefthalf.filled"];\n'
    '    DOHeaderView *headerView = [[DOHeaderView alloc] initWithImage:paleramineSymbol subtitles:@[\n'
    '        [DOGlobalAppearance mainSubtitleString:PLBuildSubtitle()],\n'
    '        [DOGlobalAppearance secondarySubtitleString:[[DOEnvironmentManager sharedManager] versionSupportString]],\n'
    '    ]];',
    count=1,
    label="main header",
)
update_block = re.compile(
    r'\n\s*dispatch_after\(dispatch_time\(DISPATCH_TIME_NOW, 0\.1 \* NSEC_PER_SEC\),.*?\n\s*\}\);\n',
    re.DOTALL,
)
ui, update_count = update_block.subn(
    '\n    // Paleramine research builds are source-pinned; upstream auto-update is disabled.\n',
    ui,
    count=1,
)
if update_count != 1:
    raise SystemExit(f"update check block: expected one replacement, found {update_count}")
ui = ui.replace("Jailbreak failed with error:", "Paleramine failed with error:")
write_text(MAIN_UI, ui)

jailbreaker = JAILBREAKER.read_text(encoding="utf-8")
jailbreaker = replace_exact(
    jailbreaker,
    '#import "spawn.h"',
    '#import "spawn.h"\n#import "../Paleramine/PLBuildIdentity.h"\n#import "../Paleramine/PLSafetyGate.h"',
    count=1,
    label="jailbreaker imports",
)
gate_anchor = (
    '- (void)runWithError:(NSError **)errOut didRemoveJailbreak:(BOOL*)didRemove showLogs:(BOOL *)showLogs\n'
    '{\n'
)
gate_code = gate_anchor + (
    '    NSError *paleramineSafetyError = PLValidatePaleramineTarget();\n'
    '    if (paleramineSafetyError) {\n'
    '        *errOut = paleramineSafetyError;\n'
    '        *showLogs = NO;\n'
    '        return;\n'
    '    }\n'
    '    [[DOUIManager sharedInstance] sendLog:PLBuildSubtitle() debug:NO];\n'
)
jailbreaker = replace_exact(jailbreaker, gate_anchor, gate_code, count=1, label="safety gate")
jailbreaker = jailbreaker.replace("Starting Jailbreak (Model:", "Starting Paleramine (Model:")
write_text(JAILBREAKER, jailbreaker)

ds = DARKSWORD.read_text(encoding="utf-8")
ds = replace_exact(
    ds,
    '#include "../kfd/Exploit/libkfd/krkw/IOSurface_shared.h"',
    '#include "../kfd/Exploit/libkfd/krkw/IOSurface_shared.h"\n#include "PLDiagnostics.h"',
    count=1,
    label="diagnostics include",
)
ds = replace_exact(
    ds,
    'int exploit_init(const char *flavor)\n{\n    init_globals();',
    'int exploit_init(const char *flavor)\n{\n    init_globals();\n    PLDiagOpen(flavor);\n'
    '    PLDiagLog("entry", 0, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "exploit_init");',
    count=1,
    label="diagnostic start",
)
geometry_anchor = '    printf("[i] searchMappingNum: %#llx\\n", searchMappingNum);\n'
geometry_new = geometry_anchor + (
    '    PLDiagLog("geometry", 0, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "stock non-A18 geometry");\n'
)
ds = replace_exact(ds, geometry_anchor, geometry_new, count=1, label="geometry log")

pass_anchor = '    NSMutableArray *targetInpGencntList = [NSMutableArray new];\n    while (true) {\n'
pass_new = (
    '    NSMutableArray *targetInpGencntList = [NSMutableArray new];\n'
    '    uint64_t paleraminePass = 0;\n'
    '    while (true) {\n'
    '        paleraminePass++;\n'
    '        PLDiagLog("pass-start", paleraminePass, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "begin heap-layout pass");\n'
)
ds = replace_exact(ds, pass_anchor, pass_new, count=1, label="pass counter")

spray_anchor = '        printf("[i] endPcbId: %llu\\n", endPcbId);\n'
spray_new = spray_anchor + (
    '        PLDiagLog("socket-spray", paleraminePass, 0, 0, successReadCount, gMlockDict.count, socketPortsCount, "socket spray complete");\n'
)
ds = replace_exact(ds, spray_anchor, spray_new, count=1, label="socket spray log")

mapping_anchor = (
    '            mach_vm_address_t searchMappingAddress = searchMappings[s].unsignedLongLongValue;\n'
    '            printf("[i] looking in search mapping: %llu\\n", s);\n'
)
mapping_new = mapping_anchor + (
    '            PLDiagLog("mapping-start", paleraminePass, s, 0, successReadCount, gMlockDict.count, socketPortsCount, "scan start");\n'
)
ds = replace_exact(ds, mapping_anchor, mapping_new, count=1, label="mapping start log")

page_anchor = '                seekingOffset += PAGE_SIZE;\n'
page_new = (
    '                seekingOffset += PAGE_SIZE;\n'
    '                uint64_t paleraminePages = seekingOffset / PAGE_SIZE;\n'
    '                if ((paleraminePages & 0x3FF) == 0) {\n'
    '                    PLDiagLog("mapping-progress", paleraminePass, s, paleraminePages, successReadCount, gMlockDict.count, socketPortsCount, "1024-page checkpoint");\n'
    '                }\n'
)
ds = replace_exact(ds, page_anchor, page_new, count=1, label="page checkpoint")

deallocate_anchor = '            kr = mach_port_deallocate(mach_task_self(), memoryObject);\n'
deallocate_new = (
    '            PLDiagLog("mapping-end", paleraminePass, s, seekingOffset / PAGE_SIZE, successReadCount, gMlockDict.count, socketPortsCount, success ? "socket acquired" : "mapping exhausted");\n'
    '            kr = mach_port_deallocate(mach_task_self(), memoryObject);\n'
)
ds = replace_exact(ds, deallocate_anchor, deallocate_new, count=1, label="mapping end log")

cleanup_anchor = (
    '        if (isA18Device) {\n'
    '            surface_munlock(wiredMapping, wiredMappingSize);\n'
    '        }\n'
    '        if (success == true) {\n'
)
cleanup_new = (
    '        if (isA18Device) {\n'
    '            surface_munlock(wiredMapping, wiredMappingSize);\n'
    '        }\n'
    '        PLDiagLog("pass-cleanup", paleraminePass, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, success ? "success" : "retry");\n'
    '        if (success == true) {\n'
)
ds = replace_exact(ds, cleanup_anchor, cleanup_new, count=1, label="pass cleanup log")

pcb_replacements = {
    '            printf("[-] Found last PCB\\n");':
        '            printf("[-] Found last PCB\\n");\n            PLDiagLog("pcb-reject", 0, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "last PCB");',
    '            printf("[-] Found freed PCB Page!\\n");':
        '            printf("[-] Found freed PCB Page!\\n");\n            PLDiagLog("pcb-reject", 0, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "freed PCB page");',
    '            printf("[-] Found old PCB Page!!!!\\n");':
        '            printf("[-] Found old PCB Page!!!!\\n");\n            PLDiagLog("pcb-reject", 0, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "old PCB page");',
    '        printf("[+] Corrupting icmp6filter pointer...\\n");':
        '        printf("[+] Corrupting icmp6filter pointer...\\n");\n        PLDiagLog("socket-corruption", 0, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "begin");',
    '                printf("[+] target corrupted: %#llx\\n", *(uint64_t *)((uintptr_t)readBuffer + pcbStartOffset + koffsetof(inpcb, icmp6filt)));':
        '                printf("[+] target corrupted: %#llx\\n", *(uint64_t *)((uintptr_t)readBuffer + pcbStartOffset + koffsetof(inpcb, icmp6filt)));\n                PLDiagLog("socket-corruption", 0, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "verified");',
}
for old, new in pcb_replacements.items():
    ds = replace_exact(ds, old, new, count=1, label=f"instrument {old[:30]}")

kernel_anchor = '    kernel_slide = kernel_base - kconstant(staticBase);\n'
kernel_new = kernel_anchor + (
    '    PLDiagLog("kernel-base", 0, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "kernel base and slide located");\n'
)
ds = replace_exact(ds, kernel_anchor, kernel_new, count=1, label="kernel base log")

return_anchor = '    return 0;\n}\n\nint exploit_deinit(void)'
return_new = (
    '    PLDiagClose("kernel primitives initialized");\n'
    '    return 0;\n'
    '}\n\nint exploit_deinit(void)'
)
ds = replace_exact(ds, return_anchor, return_new, count=1, label="diagnostic close")
write_text(DARKSWORD, ds)

with DARKSWORD_INFO.open("rb") as handle:
    exploit_info = plistlib.load(handle)
flavors = exploit_info.setdefault("DPExploitFlavors", {})
default_flavor = dict(flavors["default"])
default_flavor["DPFlavorPriority"] = 980
default_flavor["DPSupportedRanges"] = [{"Start": TARGET_VERSION, "End": TARGET_VERSION}]
default_flavor["DPSupportInclude"] = [{
    "Devices": list(TARGET_MODELS),
    "Builds": [TARGET_BUILD],
}]
flavors["paleramine-ipad5-observation"] = default_flavor
with DARKSWORD_INFO.open("wb") as handle:
    plistlib.dump(exploit_info, handle, fmt=plistlib.FMT_XML, sort_keys=False)

def png_bytes(width: int, height: int) -> bytes:
    rows = []
    for y in range(height):
        row = bytearray([0])
        for x in range(width):
            nx = (x + 0.5) / width
            ny = (y + 0.5) / height
            r = int(9 + 20 * nx)
            g = int(13 + 25 * ny)
            b = int(28 + 42 * (1.0 - nx * ny))
            cx = nx - 0.5
            shield = (abs(cx) < 0.25 * (1.0 - max(0.0, ny - 0.32) * 0.85)) and (0.18 < ny < 0.82)
            edge = abs(abs(cx) - 0.25 * (1.0 - max(0.0, ny - 0.32) * 0.85)) < 0.018
            bolt = (
                (0.48 < nx < 0.58 and 0.27 < ny < 0.52) or
                (0.40 < nx < 0.54 and 0.48 < ny < 0.57) or
                (0.44 < nx < 0.52 and 0.55 < ny < 0.73)
            )
            if shield:
                r, g, b = 42, 92, 178
            if edge:
                r, g, b = 112, 181, 255
            if bolt:
                r, g, b = 237, 247, 255
            row.extend((r, g, b, 255))
        rows.append(bytes(row))
    raw = b"".join(rows)
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    return (
        b"\x89PNG\r\n\x1a\n" +
        chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)) +
        chunk(b"IDAT", zlib.compress(raw, 9)) +
        chunk(b"IEND", b"")
    )

icon_sizes = {
    "Icon-Notification@2x.png": 40,
    "Icon-Notification@3x.png": 60,
    "Icon-Small@2x.png": 58,
    "Icon-Small@3x.png": 87,
    "Icon-38@2x.png": 76,
    "Icon-38@3x.png": 114,
    "Icon-Small-40@2x.png": 80,
    "Icon-Small-40@3x.png": 120,
    "Icon-Small-40@3x 1.png": 120,
    "Icon-60@3x.png": 180,
    "Icon-64@2x.png": 128,
    "Icon-64@3x.png": 192,
    "Icon-68@2x.png": 136,
    "Icon-76@2x.png": 152,
    "Icon-83.5@2x.png": 167,
    "Icon-Marketing.png": 1024,
}
icon_dir = ASSET_CONTENTS.parent
for filename, size in icon_sizes.items():
    (icon_dir / filename).write_bytes(png_bytes(size, size))

contents = ASSET_CONTENTS.read_text(encoding="utf-8")
contents = contents.replace(
    '"idiom" : "universal",\n      "platform" : "ios",\n      "size" : "1024x1024"',
    '"filename" : "Icon-Marketing.png",\n      "idiom" : "universal",\n      "platform" : "ios",\n      "size" : "1024x1024"',
)
write_text(ASSET_CONTENTS, contents)

manifest = dedent(f'''
brand={BRAND}
bundle_id={BUNDLE_ID}
target_models={",".join(TARGET_MODELS)}
target_version={TARGET_VERSION}
target_build={TARGET_BUILD}
stage=entry-runtime-integration
kernel_writes=existing-dopamine-path-only
livekpf=not-enabled
palera1n-bootstrap=not-enabled
diagnostic_file=Documents/Paleramine-Diagnostics.log
''').lstrip()
write_text(ROOT / "paleramine-build-manifest.txt", manifest)

print("Paleramine integration patch applied")
print(f"Brand: {BRAND}")
print(f"Bundle ID: {BUNDLE_ID}")
print(f"Target: {TARGET_MODELS} / {TARGET_VERSION} / {TARGET_BUILD}")
