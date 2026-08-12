// iOS 27 beta 3 / iPhone17,3 AppleAVE2 reachability probe.
//
// This intentionally does NOT invoke any AppleAVE2 external methods. It only
// checks whether the driver is published and whether a default user-client can
// be opened, then immediately closes it. The result is useful for correlating
// the 24A5380h firmware diff with actual app-level reachability.

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <sys/sysctl.h>

static NSString *AVECurrentBuild(void)
{
    char build[64] = {0};
    size_t size = sizeof(build) - 1;
    if (sysctlbyname("kern.osversion", build, &size, NULL, 0) != 0) {
        return @"unknown";
    }
    return [NSString stringWithUTF8String:build] ?: @"unknown";
}

static NSString *AVERegistryClass(io_registry_entry_t service)
{
    io_name_t className = {0};
    if (IOObjectGetClass(service, className) != KERN_SUCCESS) return @"unknown";
    return [NSString stringWithUTF8String:className] ?: @"unknown";
}

void DOProbeAppleAVE2Reachability(void)
{
    NSString *build = AVECurrentBuild();
    if (![build isEqualToString:@"24A5380h"] &&
        ![build isEqualToString:@"24A5390f"]) {
        NSLog(@"[iOS27Research][AppleAVE2] skipped on build %@", build);
        return;
    }

    CFMutableDictionaryRef matching = IOServiceMatching("AppleAVE2Driver");
    if (!matching) {
        NSLog(@"[iOS27Research][AppleAVE2] IOServiceMatching returned NULL on %@", build);
        return;
    }

    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (service == IO_OBJECT_NULL) {
        NSLog(@"[iOS27Research][AppleAVE2] AppleAVE2Driver NOT PUBLISHED on %@", build);
        return;
    }

    NSString *registryClass = AVERegistryClass(service);
    NSLog(@"[iOS27Research][AppleAVE2] service PUBLISHED on %@ (registry class %@)",
          build,
          registryClass);

    // Open type 0 only to test user-client reachability. No external selectors
    // or method payloads are sent by this probe.
    io_connect_t connection = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &connection);
    if (kr == KERN_SUCCESS && connection != IO_OBJECT_NULL) {
        NSLog(@"[iOS27Research][AppleAVE2] default user client OPENED on %@", build);
        IOServiceClose(connection);
    }
    else {
        NSLog(@"[iOS27Research][AppleAVE2] user-client open denied/unavailable on %@: 0x%x",
              build,
              kr);
    }

    IOObjectRelease(service);
}
