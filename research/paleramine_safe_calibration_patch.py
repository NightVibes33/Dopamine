#!/usr/bin/env python3
from __future__ import annotations

import plistlib
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_PATCH = ROOT / "research" / "paleramine_full_build_patch_base.py"
DARKSWORD = ROOT / "Application" / "Dopamine" / "Exploits" / "DarkSword" / "DarkSword.m"
DARKSWORD_INFO = ROOT / "Application" / "Dopamine" / "Exploits" / "DarkSword" / "Info.plist"
JAILBREAKER = ROOT / "Application" / "Dopamine" / "Jailbreak" / "DOJailbreaker.m"
MAIN_UI = ROOT / "Application" / "Dopamine" / "UI" / "DOMainViewController.m"
BUILD_IDENTITY = ROOT / "Application" / "Dopamine" / "Paleramine" / "PLBuildIdentity.h"

# Apply the complete Paleramine branding / target gate first.
runpy.run_path(str(BASE_PATCH), run_name="__main__")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)

# Make the app identity honest: this build calibrates only and cannot jailbreak.
identity = BUILD_IDENTITY.read_text(encoding="utf-8")
identity = replace_once(
    identity,
    '#define PL_BUILD_STAGE @"Entry + Runtime Integration"',
    '#define PL_BUILD_STAGE @"Safe Race Calibration"',
    "build stage",
)
BUILD_IDENTITY.write_text(identity, encoding="utf-8")

# Replace the main action wording so the user cannot mistake it for a jailbreak attempt.
ui = MAIN_UI.read_text(encoding="utf-8")
ui = replace_once(
    ui,
    'NSString *jailbreakButtonTitle = DOLocalizedString(@"Button_Jailbreak_Title");',
    'NSString *jailbreakButtonTitle = @"Run Safe Calibration";',
    "main calibration button",
)
MAIN_UI.write_text(ui, encoding="utf-8")

# Add a bounded calibration routine. It performs no socket spray, PCB search,
# kernel pointer corruption, bootstrap write, trust-cache upload, or userspace reboot.
ds = DARKSWORD.read_text(encoding="utf-8")
calibration_function = r'''
static int paleramine_safe_race_calibration(void)
{
    const uint64_t calibrationPages = 0x200; // 512 pages / 8 MiB on this iPad
    const mach_vm_size_t calibrationSize = calibrationPages * PAGE_SIZE;
    mach_vm_address_t calibrationAddress = 0;
    mach_port_t calibrationObject = MACH_PORT_NULL;
    mach_vm_size_t calibrationObjectSize = calibrationSize;
    uint8_t *readBuffer = calloc(1, OOB_SIZE);
    if (!readBuffer) {
        PLDiagLog("calibration-error", 0, 0, 0, successReadCount, gMlockDict.count, 0, "read buffer allocation failed");
        PLDiagClose("calibration allocation failed");
        return 77;
    }

    PLDiagLog("calibration-start", 1, 0, 0, successReadCount, gMlockDict.count, 0,
              "bounded 512-page race test; no socket spray or kernel corruption");

    pe_init();
    initialize_physical_read_write(OOB_PAGES_NUM * PAGE_SIZE);

    kern_return_t kr = mach_vm_allocate(mach_task_self(), &calibrationAddress,
                                        calibrationSize,
                                        VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
    if (kr != KERN_SUCCESS) {
        PLDiagLog("calibration-error", 1, 0, 0, successReadCount, gMlockDict.count, 0,
                  "mach_vm_allocate failed");
        goto calibration_cleanup;
    }

    for (uint64_t page = 0; page < calibrationPages; page++) {
        *(uint64_t *)(calibrationAddress + page * PAGE_SIZE) = randomMarker;
    }

    kr = mach_make_memory_entry_64(mach_task_self(), &calibrationObjectSize,
                                   calibrationAddress, VM_PROT_DEFAULT,
                                   &calibrationObject, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        PLDiagLog("calibration-error", 1, 0, 0, successReadCount, gMlockDict.count, 0,
                  "mach_make_memory_entry_64 failed");
        goto calibration_cleanup;
    }

    surface_mlock(calibrationAddress, calibrationSize);
    for (uint64_t page = 0; page < calibrationPages - OOB_PAGES_NUM; page++) {
        mach_vm_offset_t offset = page * PAGE_SIZE;
        (void)physical_oob_read_mo(calibrationObject, offset, OOB_SIZE, OOB_OFFSET, readBuffer);
        if (((page + 1) & 0x7F) == 0) {
            PLDiagLog("calibration-progress", 1, 0, page + 1, successReadCount,
                      gMlockDict.count, 0, "128-page checkpoint");
        }
    }

    PLDiagLog("calibration-result", 1, 0, calibrationPages - OOB_PAGES_NUM,
              successReadCount, gMlockDict.count, 0,
              successReadCount > 0 ? "race produced at least one OOB read" : "zero OOB reads; full exploit remains disabled");

calibration_cleanup:
    // Stop and join the race worker while every referenced object is still valid.
    goSync = 0;
    raceSync = 1;
    if (freeThreadStart != 0) {
        pthread_join(freeThread, NULL);
    }

    if (calibrationAddress != 0) {
        surface_munlock(calibrationAddress, calibrationSize);
    }
    if (calibrationObject != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), calibrationObject);
    }
    if (calibrationAddress != 0) {
        mach_vm_deallocate(mach_task_self(), calibrationAddress, calibrationSize);
    }
    if (pcAddress != 0 && pcSize != 0) {
        mach_vm_deallocate(mach_task_self(), pcAddress, pcSize);
    }
    if (pcObject != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), pcObject);
    }
    if (writeFd >= 0) close(writeFd);
    if (readFd >= 0) close(readFd);
    free(readBuffer);

    PLDiagLog("calibration-cleanup", 1, 0, 0, successReadCount, gMlockDict.count, 0,
              "all calibration resources released");
    PLDiagClose("safe calibration complete; jailbreak was not attempted");
    return 77;
}

'''

ds = replace_once(
    ds,
    '        while (raceSync == 0);\n\n        kern_return_t kr = mach_vm_map(',
    '        while (raceSync == 0);\n        if (goSync == 0) break;\n\n        kern_return_t kr = mach_vm_map(',
    "race worker stop check",
)

ds = replace_once(
    ds,
    'int exploit_init(const char *flavor)\n{',
    calibration_function + 'int exploit_init(const char *flavor)\n{',
    "calibration function insertion",
)

ds = replace_once(
    ds,
    '    PLDiagLog("entry", 0, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "exploit_init");',
    '    PLDiagLog("entry", 0, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "exploit_init");\n'
    '    if (flavor && strcmp(flavor, "paleramine-ipad5-calibration") == 0) {\n'
    '        return paleramine_safe_race_calibration();\n'
    '    }\n'
    '    PLDiagLog("blocked", 0, 0, 0, successReadCount, gMlockDict.count, socketPorts.count, "full DarkSword path disabled in calibration build");\n'
    '    PLDiagClose("full exploit blocked");\n'
    '    return 78;\n\n'
    '    /* Unreachable full DarkSword implementation retained for source comparison. */',
    "calibration dispatch",
)
DARKSWORD.write_text(ds, encoding="utf-8")

# Select only the calibration flavor for the exact iPad/build.
with DARKSWORD_INFO.open("rb") as handle:
    info = plistlib.load(handle)
flavors = info.setdefault("DPExploitFlavors", {})
base = dict(flavors.get("paleramine-ipad5-observation", flavors.get("default", {})))
base["DPFlavorPriority"] = 1000
base["DPSupportedRanges"] = [{"Start": "0.0", "End": "0.0"}]
base["DPSupportInclude"] = [{"Devices": ["iPad6,11", "iPad6,12"], "Builds": ["20H360"]}]
info["DPExploitFlavors"] = {"paleramine-ipad5-calibration": base}
with DARKSWORD_INFO.open("wb") as handle:
    plistlib.dump(info, handle, fmt=plistlib.FMT_XML, sort_keys=False)

# Convert the deliberate calibration return code into an explicit non-jailbreak result.
jailbreaker = JAILBREAKER.read_text(encoding="utf-8")
jailbreaker = replace_once(
    jailbreaker,
    '    if ([kernelExploit run] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to exploit kernel"}];',
    '    int paleramineResult = [kernelExploit run];\n'
    '    if (paleramineResult == 77) {\n'
    '        return [NSError errorWithDomain:@"PaleramineCalibration" code:77 userInfo:@{NSLocalizedDescriptionKey:@"Safe calibration completed. No jailbreak was attempted. Open Files → On My iPad → Paleramine → Paleramine-Diagnostics.log."}];\n'
    '    }\n'
    '    if (paleramineResult != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Paleramine blocked the full exploit path."}];',
    "calibration return handling",
)
JAILBREAKER.write_text(jailbreaker, encoding="utf-8")

print("Applied Paleramine safe race-calibration build")
