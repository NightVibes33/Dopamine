#!/usr/bin/env python3
"""Add low-overhead on-screen diagnostics to the iPad 5 DarkSword build.

This runs after ipad5_darksword_patch.py. It deliberately does not change exploit
parameters or race timing. It keeps stdout attached to Dopamine's log capture,
adds sparse stage updates through a runtime UI bridge, and mirrors those stage
updates to Documents/DarkSword-iPad5.log.
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
        "#include <mach/task_info.h>\n",
        "#include <mach/task_info.h>\n#include <objc/message.h>\n#include <objc/runtime.h>\n",
        "Objective-C runtime imports",
    )

    text = replace_once(
        text,
        "static unsigned gIPad5Pass = 0;\n",
        "static unsigned gIPad5Pass = 0;\n"
        "static FILE *gIPad5DiagnosticFile = NULL;\n",
        "diagnostic file global",
    )

    old_helpers = r'''static void ipad5_log_memory(const char *stage)
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

    new_helpers = r'''static void ipad5_visual_log(NSString *message, BOOL update)
{
    if (!isIPad5Device || message.length == 0) return;

    // DarkSword is a dynamically loaded framework. Resolve the app's UI manager
    // by name so this framework does not need to link against the application.
    Class managerClass = NSClassFromString(@"DOUIManager");
    SEL sharedSelector = NSSelectorFromString(@"sharedInstance");
    SEL sendSelector = NSSelectorFromString(@"sendLog:debug:update:");
    if (managerClass && [managerClass respondsToSelector:sharedSelector]) {
        id manager = ((id (*)(id, SEL))objc_msgSend)((id)managerClass, sharedSelector);
        if (manager && [manager respondsToSelector:sendSelector]) {
            ((void (*)(id, SEL, id, BOOL, BOOL))objc_msgSend)(manager,
                                                             sendSelector,
                                                             message,
                                                             NO,
                                                             update);
        }
    }

    printf("[iPad5-stage] %s\n", message.UTF8String);
    fflush(stdout);
    if (gIPad5DiagnosticFile) {
        fprintf(gIPad5DiagnosticFile, "[%s] %s\n",
                [NSDate date].description.UTF8String,
                message.UTF8String);
        fflush(gIPad5DiagnosticFile);
    }
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
    if (kr == KERN_SUCCESS) {
        printf("[iPad5] %s: resident=%llu MB virtual=%llu MB pass=%u\n",
               stage,
               (unsigned long long)(info.resident_size / (1024ULL * 1024ULL)),
               (unsigned long long)(info.virtual_size / (1024ULL * 1024ULL)),
               gIPad5Pass);
        if (gIPad5DiagnosticFile) {
            fprintf(gIPad5DiagnosticFile,
                    "[%s] memory stage=%s resident=%lluMB virtual=%lluMB pass=%u\n",
                    [NSDate date].description.UTF8String,
                    stage,
                    (unsigned long long)(info.resident_size / (1024ULL * 1024ULL)),
                    (unsigned long long)(info.virtual_size / (1024ULL * 1024ULL)),
                    gIPad5Pass);
            fflush(gIPad5DiagnosticFile);
        }
    } else {
        printf("[iPad5] %s: task_info failed: %s\n", stage, mach_error_string(kr));
    }
    fflush(stdout);
}

static void ipad5_enable_persistent_log(void)
{
    // Keep stdout attached to Dopamine's capture. Redirecting it made the UI
    // appear frozen after kernelConstant.pointer_mask.
    setvbuf(stdout, NULL, _IONBF, 0);

    NSString *documents = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                               NSUserDomainMask,
                                                               YES).firstObject;
    if (documents) {
        NSString *logPath = [documents stringByAppendingPathComponent:@"DarkSword-iPad5.log"];
        gIPad5DiagnosticFile = fopen(logPath.fileSystemRepresentation, "a+");
        if (gIPad5DiagnosticFile) setvbuf(gIPad5DiagnosticFile, NULL, _IONBF, 0);
        printf("[iPad5] stage log: %s\n", logPath.fileSystemRepresentation);
    }

    printf("\n========== iPad 5 DarkSword session %s ==========\n",
           [NSDate date].description.UTF8String);
    fflush(stdout);
}

'''
    text = replace_once(text, old_helpers, new_helpers, "stdout-preserving diagnostic helpers")

    text = replace_once(
        text,
        '        printf("[iPad5] experimental low-memory DarkSword profile enabled\\n");\n'
        '        ipad5_log_memory("exploit-init");\n',
        '        printf("[iPad5] experimental low-memory DarkSword profile enabled\\n");\n'
        '        ipad5_visual_log(@"DarkSword 1/6: iPad 5 profile initialized", NO);\n'
        '        ipad5_log_memory("exploit-init");\n',
        "profile initialized stage",
    )

    text = replace_once(
        text,
        '            printf("[iPad5] starting heap-layout pass %u\\n", gIPad5Pass);\n'
        '            ipad5_log_memory("pass-start");\n',
        '            printf("[iPad5] starting heap-layout pass %u\\n", gIPad5Pass);\n'
        '            ipad5_visual_log([NSString stringWithFormat:@"DarkSword 2/6: Heap-layout pass %u", gIPad5Pass], NO);\n'
        '            ipad5_log_memory("pass-start");\n',
        "heap pass stage",
    )

    text = replace_once(
        text,
        '            printf("[iPad5] socket spray target: %u\\n", socketTarget);\n'
        '        }\n'
        '        for (unsigned socketCount = 0; socketCount < socketTarget; socketCount++) {\n',
        '            printf("[iPad5] socket spray target: %u\\n", socketTarget);\n'
        '            ipad5_visual_log([NSString stringWithFormat:@"DarkSword 3/6: Spraying %u sockets", socketTarget], YES);\n'
        '        }\n'
        '        for (unsigned socketCount = 0; socketCount < socketTarget; socketCount++) {\n',
        "socket spray stage",
    )

    text = replace_once(
        text,
        '            printf("[i] looking in search mapping: %llu\\n", s);\n',
        '            printf("[i] looking in search mapping: %llu\\n", s);\n'
        '            if (isIPad5Device) {\n'
        '                ipad5_visual_log([NSString stringWithFormat:@"DarkSword 3/6: Scanning memory window %llu/%llu", s + 1, searchMappingNum], YES);\n'
        '            }\n',
        "mapping scan stage",
    )

    text = replace_once(
        text,
        '            printf("[+] Found control_socket at idx: %u\\n", controlSocketIdx);\n',
        '            printf("[+] Found control_socket at idx: %u\\n", controlSocketIdx);\n'
        '            if (isIPad5Device) ipad5_visual_log(@"DarkSword 4/6: Kernel socket primitive found", NO);\n',
        "primitive-found stage",
    )

    text = replace_once(
        text,
        '        pe_init();\n'
        '        if (isIPad5Device) ipad5_log_memory("before-pe-v1");\n'
        '        pe_v1();\n'
        '        if (isIPad5Device) ipad5_log_memory("pe-v1-success");\n',
        '        if (isIPad5Device) ipad5_visual_log(@"DarkSword 1/6: Initializing race primitives", NO);\n'
        '        pe_init();\n'
        '        if (isIPad5Device) {\n'
        '            ipad5_log_memory("before-pe-v1");\n'
        '            ipad5_visual_log(@"DarkSword 2/6: Beginning heap search", NO);\n'
        '        }\n'
        '        pe_v1();\n'
        '        if (isIPad5Device) {\n'
        '            ipad5_log_memory("pe-v1-success");\n'
        '            ipad5_visual_log(@"DarkSword 4/6: Early kernel read/write is stable", NO);\n'
        '        }\n',
        "exploit core stages",
    )

    text = replace_once(
        text,
        '    kernel_base = textPtr & 0xFFFFFFFFFFFFC000;\n'
        '    while (true) {\n',
        '    kernel_base = textPtr & 0xFFFFFFFFFFFFC000;\n'
        '    uint64_t kernelScanPages = 0;\n'
        '    if (isIPad5Device) ipad5_visual_log(@"DarkSword 5/6: Locating kernel base", NO);\n'
        '    while (true) {\n',
        "kernel-base scan start",
    )

    text = replace_once(
        text,
        '        kernel_base -= PAGE_SIZE;\n'
        '    }\n'
        '    kernel_slide = kernel_base - kconstant(staticBase);\n',
        '        kernel_base -= PAGE_SIZE;\n'
        '        kernelScanPages++;\n'
        '        if (isIPad5Device && (kernelScanPages % 2048) == 0) {\n'
        '            ipad5_visual_log([NSString stringWithFormat:@"DarkSword 5/6: Kernel scan %,llu pages", kernelScanPages], YES);\n'
        '        }\n'
        '    }\n'
        '    kernel_slide = kernel_base - kconstant(staticBase);\n'
        '    if (isIPad5Device) {\n'
        '        ipad5_visual_log([NSString stringWithFormat:@"DarkSword 5/6: Kernel base found after %,llu pages", kernelScanPages], NO);\n'
        '    }\n',
        "kernel-base scan progress",
    )

    text = replace_once(
        text,
        '    printf("kread64(%#llx) -> %#llx\\n", kernel_base, kread64(kernel_base));\n\n'
        '    return 0;\n',
        '    printf("kread64(%#llx) -> %#llx\\n", kernel_base, kread64(kernel_base));\n'
        '    if (isIPad5Device) ipad5_visual_log(@"DarkSword 6/6: Exploit completed successfully", NO);\n\n'
        '    return 0;\n',
        "exploit completion stage",
    )

    TARGET.write_text(text, encoding="utf-8")
    print(f"Added visible DarkSword diagnostics to {TARGET}")


if __name__ == "__main__":
    main()
