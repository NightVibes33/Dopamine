//
//  DOMainViewController.m
//  Dopamine
//
//  Created by tomt000 on 08/01/2024.
//

#import "DOMainViewController.h"
#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import "DOJailbreaker.h"
#import "DOGlobalAppearance.h"
#import "DOActionMenuButton.h"
#import "DOUpdateViewController.h"
#import "DOLogCrashViewController.h"
#import <pthread.h>
#import <sys/sysctl.h>
#import <IOKit/IOKitLib.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <sys/stat.h>
#import <xpc/xpc.h>
#import <libjailbreak/libjailbreak.h>


typedef void *DOContainerQuery;
typedef void *DOContainerObject;


static NSString *DOIOReturnName(kern_return_t kr)
{
    switch ((uint32_t)kr) {
        case 0x00000000: return @"kIOReturnSuccess";
        case 0xe00002bd: return @"kIOReturnNoMemory";
        case 0xe00002be: return @"kIOReturnNoResources";
        case 0xe00002c0: return @"kIOReturnNoDevice";
        case 0xe00002c1: return @"kIOReturnNotPrivileged";
        case 0xe00002c2: return @"kIOReturnBadArgument";
        case 0xe00002c7: return @"kIOReturnUnsupported";
        case 0xe00002d8: return @"kIOReturnNotOpen";
        case 0xe00002e2: return @"kIOReturnNotPermitted";
        default: return @"IOReturnUnknown";
    }
}

static NSArray<NSString *> *DORuntimeEntitlementInventory(void)
{
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
    if (!security) {
        [lines addObject:@"Runtime entitlement inventory: UNAVAILABLE"];
        return lines;
    }

    CFTypeRef (*taskFromSelf)(CFAllocatorRef) = dlsym(security, "SecTaskCreateFromSelf");
    CFTypeRef (*copyValue)(CFTypeRef, CFStringRef, CFErrorRef *) =
        dlsym(security, "SecTaskCopyValueForEntitlement");
    if (!taskFromSelf || !copyValue) {
        [lines addObject:@"Runtime entitlement inventory: SYMBOLS UNAVAILABLE"];
        dlclose(security);
        return lines;
    }

    CFTypeRef task = taskFromSelf(kCFAllocatorDefault);
    NSArray<NSString *> *keys = @[
        @"platform-application",
        @"com.apple.private.security.no-sandbox",
        @"com.apple.security.exception.iokit-user-client-class",
        @"com.apple.developer.kernel.extended-virtual-addressing",
        @"com.apple.developer.kernel.increased-memory-limit"
    ];
    for (NSString *key in keys) {
        CFTypeRef value = task ? copyValue(task, (__bridge CFStringRef)key, NULL) : NULL;
        [lines addObject:[NSString stringWithFormat:@"Runtime entitlement %@: %@",
                          key, value ? @"PRESENT" : @"ABSENT"]];
        if (value) CFRelease(value);
    }
    if (task) CFRelease(task);
    dlclose(security);
    return lines;
}

static NSString *DORegistryScalarDescription(io_service_t service, CFStringRef key)
{
    CFTypeRef value = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
    if (!value) return @"ABSENT";

    NSString *description = nil;
    if (CFGetTypeID(value) == CFStringGetTypeID()) {
        description = [(__bridge NSString *)value copy];
    } else if (CFGetTypeID(value) == CFNumberGetTypeID() ||
               CFGetTypeID(value) == CFBooleanGetTypeID()) {
        description = [(__bridge id)value description];
    } else if (CFGetTypeID(value) == CFArrayGetTypeID()) {
        description = [NSString stringWithFormat:@"ARRAY (%ld entries)",
                       (long)CFArrayGetCount((CFArrayRef)value)];
    } else if (CFGetTypeID(value) == CFDictionaryGetTypeID()) {
        description = [NSString stringWithFormat:@"DICTIONARY (%ld keys)",
                       (long)CFDictionaryGetCount((CFDictionaryRef)value)];
    } else if (CFGetTypeID(value) == CFDataGetTypeID()) {
        description = [NSString stringWithFormat:@"DATA (%ld bytes)",
                       (long)CFDataGetLength((CFDataRef)value)];
    } else {
        description = @"PRESENT (unreported type)";
    }
    CFRelease(value);
    return description ?: @"PRESENT";
}

static NSArray<NSString *> *DOAppleAVE2Diagnostic(void)
{
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault,
                                                        IOServiceMatching("AppleAVE2Driver"));
    if (service == IO_OBJECT_NULL) {
        [lines addObject:@"AppleAVE2 canonical service: NOT FOUND"];
        [lines addObject:@"AppleAVE2 reachable: NO"];
        return lines;
    }

    io_name_t className = {0};
    io_string_t registryPath = {0};
    kern_return_t classResult = IOObjectGetClass(service, className);
    kern_return_t pathResult = IORegistryEntryGetPath(service, kIOServicePlane, registryPath);
    [lines addObject:@"AppleAVE2 canonical service: FOUND"];
    [lines addObject:[NSString stringWithFormat:@"IORegistry class: %@",
                      classResult == KERN_SUCCESS ? [NSString stringWithUTF8String:className] : @"UNAVAILABLE"]];
    [lines addObject:[NSString stringWithFormat:@"IORegistry path: %@",
                      pathResult == KERN_SUCCESS ? [NSString stringWithUTF8String:registryPath] : @"UNAVAILABLE"]];

    // Read only published registry metadata. Values that may contain opaque binary
    // policy data are reported by type/size rather than copied into the report.
    NSArray<NSString *> *contractKeys = @[
        @"IOUserClientClass",
        @"IOProviderClass",
        @"CFBundleIdentifier",
        @"IOUserClientCreator",
        @"IOUserClientCrossEndianCompatible",
        @"IOUserClientProperties"
    ];
    [lines addObject:@"AppleAVE2 published initialization contract:"];
    for (NSString *key in contractKeys) {
        [lines addObject:[NSString stringWithFormat:@"  %@: %@",
                          key,
                          DORegistryScalarDescription(service, (__bridge CFStringRef)key)]];
    }

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW | RTLD_LOCAL);
    CFStringRef (*copySuperclass)(CFStringRef) = iokit ? dlsym(iokit, "IOObjectCopySuperclassForClass") : NULL;
    if (classResult == KERN_SUCCESS && copySuperclass) {
        NSMutableArray<NSString *> *hierarchy = [NSMutableArray array];
        CFStringRef current = CFStringCreateWithCString(kCFAllocatorDefault, className, kCFStringEncodingUTF8);
        for (NSUInteger depth = 0; current && depth < 8; depth++) {
            [hierarchy addObject:(__bridge NSString *)current];
            CFStringRef next = copySuperclass(current);
            CFRelease(current);
            current = next;
        }
        if (current) CFRelease(current);
        [lines addObject:[NSString stringWithFormat:@"IORegistry class hierarchy: %@",
                          [hierarchy componentsJoinedByString:@" -> "]]];
    } else {
        [lines addObject:@"IORegistry class hierarchy: UNAVAILABLE"];
    }
    if (iokit) dlclose(iokit);

    BOOL openedAnyClient = NO;
    for (uint32_t type = 0; type <= 5; type++) {
        io_connect_t connection = IO_OBJECT_NULL;
        kern_return_t kr = IOServiceOpen(service, mach_task_self(), type, &connection);
        [lines addObject:[NSString stringWithFormat:@"User client %u: %@ (%@, 0x%08x)",
                          type,
                          kr == KERN_SUCCESS ? @"OPEN" : @"DENIED",
                          DOIOReturnName(kr),
                          (uint32_t)kr]];
        if (type == 0) {
            [lines addObject:@"Client 0 probe mode: NORMAL OPEN/CLOSE ONLY; no input structure or selector calls"];
            [lines addObject:@"Client 0 interpretation: open-time failure occurs before any external method call"];
        }
        if (kr == KERN_SUCCESS) {
            openedAnyClient = YES;
            IOServiceClose(connection);
        }
    }
    IOObjectRelease(service);
    [lines addObject:[NSString stringWithFormat:@"AppleAVE2 reachable: %@",
                      openedAnyClient ? @"YES" : @"NO"]];
    return lines;
}


static NSArray<NSString *> *DOBadQueryAccessMap(void)
{
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    void *lib = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
        [lines addObject:@"bad_query access map: CMG LIBRARY UNAVAILABLE"];
        return lines;
    }

    DOContainerQuery (*queryCreate)(void) = dlsym(lib, "container_query_create");
    void (*queryFree)(DOContainerQuery) = dlsym(lib, "container_query_free");
    void (*setClass)(DOContainerQuery, uint64_t) = dlsym(lib, "container_query_set_class");
    void (*setGroups)(DOContainerQuery, xpc_object_t) = dlsym(lib, "container_query_set_group_identifiers");
    void (*setFlags)(DOContainerQuery, uint64_t) = dlsym(lib, "container_query_operation_set_flags");
    void (*setPart)(DOContainerQuery, uint64_t) = dlsym(lib, "container_query_operation_set_part");
    void (*setPartDomain)(DOContainerQuery, const char *) = dlsym(lib, "container_query_operation_set_part_domain");
    DOContainerObject (*singleResult)(DOContainerQuery) = dlsym(lib, "container_query_get_single_result");
    char *(*copyToken)(DOContainerObject) = dlsym(lib, "container_copy_sandbox_token");
    int64_t (*consumeToken)(const char *) = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    int (*releaseToken)(int64_t) = dlsym(RTLD_DEFAULT, "sandbox_extension_release");

    if (!queryCreate || !queryFree || !setClass || !setGroups || !setFlags ||
        !setPart || !setPartDomain || !singleResult || !copyToken || !consumeToken) {
        [lines addObject:@"bad_query access map: REQUIRED SYMBOLS INCOMPLETE"];
        dlclose(lib);
        return lines;
    }

    NSArray<NSDictionary<NSString *, NSString *> *> *targets = @[
        @{@"name": @"App data root", @"path": @"/var/containers/Data/Application"},
        @{@"name": @"App-group root", @"path": @"/var/mobile/Containers/Shared/AppGroup"},
        @{@"name": @"System data root", @"path": @"/var/containers/Data/System"},
        @{@"name": @"System-group root", @"path": @"/var/containers/Shared/SystemGroup"},
        @{@"name": @"MobileGestalt system group", @"path": @"/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache"}
    ];

    [lines addObject:@"bad_query access map: NON-DESTRUCTIVE ROOT CHECKS"];
    for (NSDictionary<NSString *, NSString *> *target in targets) {
        NSString *name = target[@"name"];
        NSString *path = target[@"path"];
        DOContainerQuery query = queryCreate();
        int64_t handle = -1;
        BOOL tokenActive = NO;

        if (query) {
            setClass(query, 13);
            xpc_object_t identifier = xpc_string_create("systemgroup.com.apple.mobilegestaltcache");
            setGroups(query, identifier);
            setPart(query, 3);
            NSString *domain = [@"../../../../../../../.." stringByAppendingString:path];
            setPartDomain(query, domain.fileSystemRepresentation);
            setFlags(query, 0x0000008000000000ULL);

            DOContainerObject object = singleResult(query);
            char *token = object ? copyToken(object) : NULL;
            if (token) {
                handle = consumeToken(token);
                tokenActive = handle >= 0;
                free(token);
            }
            queryFree(query);
        }

        struct stat st = {0};
        BOOL exists = lstat(path.fileSystemRepresentation, &st) == 0;
        int readFD = open(path.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        BOOL readable = readFD >= 0;
        if (readFD >= 0) close(readFD);
        BOOL writePermitted = access(path.fileSystemRepresentation, W_OK) == 0;

        [lines addObject:[NSString stringWithFormat:@"%@: token %@; exists %@; read %@; write-permission %@",
                          name,
                          tokenActive ? @"ACTIVE" : @"FAILED",
                          exists ? @"YES" : @"NO",
                          readable ? @"YES" : @"NO",
                          writePermitted ? @"YES" : @"NO"]];

        if (handle >= 0 && releaseToken) releaseToken(handle);
    }

    [lines addObject:@"bad_query map enumerated child names: NO"];
    [lines addObject:@"bad_query map opened user files: NO"];
    [lines addObject:@"bad_query map created/changed bytes: NO"];
    dlclose(lib);
    return lines;
}

static NSArray<NSString *> *DORunCMGSandboxProbe(void)
{
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    void *lib = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
        [lines addObject:@"CMG library: UNAVAILABLE"];
        return lines;
    }

    DOContainerQuery (*queryCreate)(void) = dlsym(lib, "container_query_create");
    void (*queryFree)(DOContainerQuery) = dlsym(lib, "container_query_free");
    void (*setClass)(DOContainerQuery, uint64_t) = dlsym(lib, "container_query_set_class");
    void (*setTransient)(DOContainerQuery, bool) = dlsym(lib, "container_query_set_transient");
    void (*setGroups)(DOContainerQuery, xpc_object_t) = dlsym(lib, "container_query_set_group_identifiers");
    void (*setPlatform)(DOContainerQuery, uint64_t) = dlsym(lib, "container_query_operation_set_platform");
    void (*setFlags)(DOContainerQuery, uint64_t) = dlsym(lib, "container_query_operation_set_flags");
    void (*setPart)(DOContainerQuery, uint64_t) = dlsym(lib, "container_query_operation_set_part");
    DOContainerObject (*singleResult)(DOContainerQuery) = dlsym(lib, "container_query_get_single_result");
    bool (*activate)(DOContainerObject, bool) = dlsym(lib, "container_object_sandbox_extension_activate");
    const char *(*getPath)(DOContainerObject) = dlsym(lib, "container_object_get_path");

    if (!queryCreate || !queryFree || !setClass || !setTransient || !setGroups ||
        !setPlatform || !setFlags || !singleResult || !activate || !getPath) {
        [lines addObject:@"CMG symbols: INCOMPLETE"];
        dlclose(lib);
        return lines;
    }

    DOContainerQuery query = queryCreate();
    if (!query) {
        [lines addObject:@"CMG query: FAILED"];
        dlclose(lib);
        return lines;
    }

    setClass(query, 13);
    setTransient(query, false);
    xpc_object_t groups = xpc_array_create(NULL, 0);
    xpc_array_set_string(groups, XPC_ARRAY_APPEND, "systemgroup.com.apple.mobilegestaltcache");
    setGroups(query, groups);
    setPlatform(query, 2);
    setFlags(query, (1ULL << 32) | (1ULL << 39));
    if (setPart) setPart(query, 3);

    DOContainerObject object = singleResult(query);
    BOOL extensionActive = object && activate(object, true);
    NSString *containerPath = nil;
    if (extensionActive) {
        const char *rawPath = getPath(object);
        if (rawPath) containerPath = [NSString stringWithUTF8String:rawPath];
    }

    [lines addObject:[NSString stringWithFormat:@"CMG sandbox extension: %@",
                      extensionActive ? @"ACTIVE" : @"FAILED"]];

    if (containerPath.length) {
        NSString *plist = [containerPath stringByAppendingPathComponent:@"com.apple.MobileGestalt.plist"];
        int fd = open(plist.fileSystemRepresentation, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd >= 0) {
            int flags = fcntl(fd, F_GETFL);
            BOOL writeCapable = flags >= 0 &&
                (((flags & O_ACCMODE) == O_WRONLY) || ((flags & O_ACCMODE) == O_RDWR));
            [lines addObject:[NSString stringWithFormat:@"MobileGestalt open-only access: %@",
                              writeCapable ? @"WRITE-CAPABLE FD" : @"READ-ONLY/UNKNOWN"]];
            close(fd);
        } else {
            [lines addObject:[NSString stringWithFormat:@"MobileGestalt open-only access: DENIED (errno %d)", errno]];
        }
    } else {
        [lines addObject:@"MobileGestalt open-only access: NOT TESTED"];
    }

    queryFree(query);
    dlclose(lib);
    [lines addObject:@"CMG probe wrote bytes: NO"];
    [lines addObject:@"Source credit: rooootdev/mond; bad_query research by forcequitOS"];
    return lines;
}

@interface DOMainViewController ()

@property DOJailbreakButton *jailbreakBtn;
@property NSArray<NSLayoutConstraint *> *jailbreakButtonConstraints;
@property DOActionMenuButton *updateButton;
@property(nonatomic) BOOL hideStatusBar;
@property(nonatomic) BOOL hideHomeIndicator;

@end

@implementation DOMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self setupStack];
}

-(void)setupStack
{
    UIStackView *stackView = [[UIStackView alloc] init];
    [stackView setAxis:UILayoutConstraintAxisVertical];
    [stackView setAlignment:UIStackViewAlignmentTrailing];
    [stackView setDistribution:UIStackViewDistributionEqualSpacing];
    [stackView setTranslatesAutoresizingMaskIntoConstraints:NO];

    [self.view addSubview:stackView];


    int statusBarHeight = fmax(15, [[UIApplication sharedApplication] keyWindow].safeAreaInsets.top - 20);

    [NSLayoutConstraint activateConstraints:@[
        [stackView.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:statusBarHeight],//-35
        [stackView.heightAnchor constraintEqualToAnchor:self.view.heightAnchor multiplier:[DOGlobalAppearance isHomeButtonDevice] ? 0.78 : 0.73]
    ]];

    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad)
    {
        NSLayoutConstraint *relativeWidthConstraint = [stackView.widthAnchor constraintEqualToAnchor:self.view.widthAnchor multiplier:0.8];
        relativeWidthConstraint.priority = UILayoutPriorityDefaultHigh;
        NSLayoutConstraint *maxWidthConstraint = [stackView.widthAnchor constraintLessThanOrEqualToConstant:UI_IPAD_MAX_WIDTH];
        maxWidthConstraint.priority = UILayoutPriorityRequired;

        [NSLayoutConstraint activateConstraints:@[
            relativeWidthConstraint,
            maxWidthConstraint,
            [stackView.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor]
        ]];
    }
    else
    {
        [NSLayoutConstraint activateConstraints:@[
            [stackView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:UI_PADDING],
            [stackView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-UI_PADDING],
        ]];
    }

    //Header
    DOHeaderView *headerView = [[DOHeaderView alloc] initWithImage: [UIImage imageNamed:@"Dopamine"] subtitles: @[
        [DOGlobalAppearance mainSubtitleString:[[DOEnvironmentManager sharedManager] versionSupportString]],
        [DOGlobalAppearance secondarySubtitleString:DOLocalizedString(@"Credits_Made_By")],
    ]];
    
    [stackView addArrangedSubview:headerView];

    [NSLayoutConstraint activateConstraints:@[
        [headerView.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor constant:5],
        [headerView.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor]
    ]];
    
    //Action Menu
    DOActionMenuView *actionView = [[DOActionMenuView alloc] initWithActions:@[
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Settings_Title") image:[UIImage systemImageNamed:@"gearshape" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"settings" handler:^(__kindof UIAction * _Nonnull action) {
            [self.navigationController pushViewController:[[DOSettingsController alloc] init] animated:YES];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Restart_SpringBoard_Title") image:[UIImage systemImageNamed:@"arrow.clockwise" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"respring" handler:^(__kindof UIAction * _Nonnull action) {
            [self fadeToBlack:^{
                [[DOEnvironmentManager sharedManager] respring];
            }];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Reboot_Userspace_Title") image:[UIImage systemImageNamed:@"arrow.clockwise.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"reboot-userspace" handler:^(__kindof UIAction * _Nonnull action) {
            [self fadeToBlack:^{
                [[DOEnvironmentManager sharedManager] rebootUserspace];
            }];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Credits_Title") image:[UIImage systemImageNamed:@"info.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"credits" handler:^(__kindof UIAction * _Nonnull action) {
            [self.navigationController pushViewController:[[DOCreditsViewController alloc] init] animated:YES];
        }]
    ] delegate:self];
    
    [stackView addArrangedSubview: actionView];

    [NSLayoutConstraint activateConstraints:@[
        [actionView.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor],
        [actionView.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor],
    ]];
    
    
    UIView *buttonPlaceHolder = [[UIView alloc] init];
    [buttonPlaceHolder setTranslatesAutoresizingMaskIntoConstraints:NO];
    [stackView addArrangedSubview:buttonPlaceHolder];
    [NSLayoutConstraint activateConstraints:@[
        [buttonPlaceHolder.heightAnchor constraintEqualToConstant:60]
    ]];
    
    //Jailbreak Button
    BOOL isJailbroken = [[DOEnvironmentManager sharedManager] isJailbroken] || [[DOEnvironmentManager sharedManager] isJailbrokenWithOtherJailbreak];
    BOOL isSupported = [[DOEnvironmentManager sharedManager] isSupported];

    NSString *jailbreakButtonTitle = [self jailbreakButtonTitle];
        
    UIImage *jailbreakButtonImage;
    if (isSupported)
        jailbreakButtonImage = [UIImage systemImageNamed:@"lock.open" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]];
    else
        jailbreakButtonImage = [UIImage systemImageNamed:@"lock.slash" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]];
    
    self.jailbreakBtn = [[DOJailbreakButton alloc] initWithAction: [UIAction actionWithTitle:jailbreakButtonTitle image:jailbreakButtonImage identifier:@"jailbreak" handler:^(__kindof UIAction * _Nonnull action) {
        if (![[DOEnvironmentManager sharedManager] isSupported]) {
            [self runIOS27Diagnostics];
            return;
        }

        [actionView hide];
        [self.jailbreakBtn expandButton: self.jailbreakButtonConstraints];

        self.updateButton.userInteractionEnabled = NO;
        [UIView animateWithDuration:0.75 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0  options: UIViewAnimationOptionCurveEaseInOut animations:^{
            [headerView setTransform:CGAffineTransformMakeTranslation(0, -25)];
            self.updateButton.alpha = 0;
        } completion:nil];
        
        [self startJailbreak];
        
    }]];
    // Unsupported research targets may run diagnostics, but never enter the jailbreak chain.
    self.jailbreakBtn.enabled = !isJailbroken;

    [self.view addSubview:self.jailbreakBtn];

    [NSLayoutConstraint activateConstraints:(self.jailbreakButtonConstraints = @[
        [self.jailbreakBtn.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor],
        [self.jailbreakBtn.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor],
        [self.jailbreakBtn.heightAnchor constraintEqualToAnchor:buttonPlaceHolder.heightAnchor],
        [self.jailbreakBtn.centerYAnchor constraintEqualToAnchor:buttonPlaceHolder.centerYAnchor]
    ])];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.1 * NSEC_PER_SEC), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        if ([[DOUIManager sharedInstance] environmentUpdateAvailable])
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self setupUpdateAvailable:YES];
            });
        }
        else if ([[DOUIManager sharedInstance] isUpdateAvailable])
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self setupUpdateAvailable:NO];
            });
        }
    });
}

- (NSString *)jailbreakButtonTitle
{
    BOOL isJailbroken = [[DOEnvironmentManager sharedManager] isJailbroken];
    BOOL isSupported = [[DOEnvironmentManager sharedManager] isSupported];
    BOOL removeJailbreakEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"removeJailbreakEnabled" fallback:NO];

    NSString *jailbreakButtonTitle = DOLocalizedString(@"Button_Jailbreak_Title");
    if (!isSupported)
        jailbreakButtonTitle = @"Run iOS 27 Diagnostics";
    else if (isJailbroken)
        jailbreakButtonTitle = DOLocalizedString(@"Status_Title_Jailbroken");
    else if (removeJailbreakEnabled)
        jailbreakButtonTitle = DOLocalizedString(@"Button_Remove_Jailbreak");
    
    return jailbreakButtonTitle;
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    [self.jailbreakBtn.button setTitle:[self jailbreakButtonTitle] forState:UIControlStateNormal];
}

- (void)runIOS27Diagnostics
{
    self.jailbreakBtn.enabled = NO;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        NSMutableArray<NSString *> *lines = [NSMutableArray array];
        UIDevice *device = [UIDevice currentDevice];

        char machine[256] = {0};
        size_t machineSize = sizeof(machine);
        if (sysctlbyname("hw.machine", machine, &machineSize, NULL, 0) != 0) {
            machine[0] = '?';
            machine[1] = '\\0';
        }

        [lines addObject:@"Dopamine iOS 27 research diagnostics"];
        [lines addObject:[NSString stringWithFormat:@"Device: %s", machine]];
        [lines addObject:[NSString stringWithFormat:@"System: %@ %@", device.systemName, device.systemVersion]];
        [lines addObject:[NSString stringWithFormat:@"Build: %@", [[DOEnvironmentManager sharedManager] nightlyHash] ?: @"release"]];

        NSString *probePath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"dopamine-ios27-rw-probe"];
        NSData *expected = [@"DOPAMINE_IOS27_CONTAINER_RW" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *writeError = nil;
        BOOL wrote = [expected writeToFile:probePath options:NSDataWritingAtomic error:&writeError];
        NSData *readBack = wrote ? [NSData dataWithContentsOfFile:probePath] : nil;
        BOOL containerRW = wrote && [readBack isEqualToData:expected];
        [[NSFileManager defaultManager] removeItemAtPath:probePath error:nil];
        [lines addObject:[NSString stringWithFormat:@"App-container read/write: %@", containerRW ? @"PASS" : @"FAIL"]];
        if (writeError) {
            [lines addObject:[NSString stringWithFormat:@"Container error: %@", writeError.localizedDescription]];
        }

        [lines addObjectsFromArray:DORunCMGSandboxProbe()];
        [lines addObjectsFromArray:DOBadQueryAccessMap()];

        [lines addObjectsFromArray:DORuntimeEntitlementInventory()];
        [lines addObjectsFromArray:DOAppleAVE2Diagnostic()];
        [lines addObject:@"Kernel read/write: NOT PROVEN"];
        [lines addObject:@"SPTM bypass: NOT AVAILABLE"];
        [lines addObject:@"Jailbreak result: NOT AVAILABLE"];
        [lines addObject:@"Opening a user client is reachability evidence only; it is not kernel read/write."];

        NSString *report = [lines componentsJoinedByString:@"\n"];
        NSLog(@"%@", report);

        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"iOS 27 Diagnostic Result"
                                                                            message:report
                                                                     preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Copy Results"
                                                     style:UIAlertActionStyleDefault
                                                   handler:^(__kindof UIAlertAction *action) {
                UIPasteboard.generalPasteboard.string = report;
            }]];
            [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
            self.jailbreakBtn.enabled = YES;
        });
    });
}

- (void)startJailbreak
{
    DOJailbreaker *jailbreaker = [[DOJailbreaker alloc] init];

    [[DOUIManager sharedInstance] startLogCapture];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        if ([jailbreaker contiguousMappingWorkaroundNeeded]) {
            
            cpu_subtype_t cpuFamily = 0;
            size_t cpuFamilySize = sizeof(cpuFamily);
            sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);
            NSString *workaroundMessage = DOLocalizedString(@"Respring_Required_Message");
            if (cpuFamily == CPUFAMILY_ARM_TYPHOON) {
                workaroundMessage = [workaroundMessage stringByAppendingString:[NSString stringWithFormat:@"\n\n%@", DOLocalizedString(@"Respring_Required_Notice_A8")]];
            }

            UIAlertController *contiguousMappingWorkaroundAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Respring_Required") message:workaroundMessage preferredStyle:UIAlertControllerStyleAlert];
            
            UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Respring_Cancel") style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
                exit(0);
            }];
            
            UIAlertAction *workaroundAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Apply_Workaround") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                [jailbreaker applyContiguousMappingWorkaround];
            }];
            
            [contiguousMappingWorkaroundAlertController addAction:cancelAction];
            [contiguousMappingWorkaroundAlertController addAction:workaroundAction];
            contiguousMappingWorkaroundAlertController.preferredAction = workaroundAction;

            dispatch_async(dispatch_get_main_queue(), ^{
                [self presentViewController:contiguousMappingWorkaroundAlertController animated:YES completion:nil];
            });
            return;
        }

        //We need to get the preconfig mutex to start the jailbreak (self.jailbreakBtn.canStartJailbreak)
        [self.jailbreakBtn lockMutex];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.hideHomeIndicator = YES;
        });

        NSError *error;
        BOOL didRemove = NO;
        BOOL showLogs = YES;
        [jailbreaker runWithError:&error didRemoveJailbreak:&didRemove showLogs:&showLogs];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error && showLogs) {
                [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"Jailbreak failed with error: %@", error] debug:NO];
                [self.navigationController pushViewController:[[DOLogCrashViewController alloc] initWithTitle:[error localizedDescription]] animated:YES];
            }
            else if (error && !showLogs) {
                // Used when there is an error that is explainable in such detail that additional logs are not needed
                UIAlertController *alertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Log_Error") message:[error localizedDescription] preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *rebootAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Reboot") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                    exec_cmd_trusted(JBROOT_PATH("/sbin/reboot"), NULL);
                }];
                [alertController addAction:rebootAction];
                [self presentViewController:alertController animated:YES completion:nil];
            }
            else if (didRemove) {
                UIAlertController *alertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Removed_Jailbreak_Alert_Title") message:DOLocalizedString(@"Removed_Jailbreak_Alert_Message") preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *rebootAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Close") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                    exit(0);
                }];
                [alertController addAction:rebootAction];
                [self presentViewController:alertController animated:YES completion:nil];
            }
            else {
                // No errors
                [[DOUIManager sharedInstance] completeJailbreak];
                [self fadeToBlack: ^{
                    [jailbreaker finalize];
                }];
            }
        });
        [self.jailbreakBtn unlockMutex];
    });
}

-(void)setupUpdateAvailable:(BOOL)environmentUpdate
{
    if (self.jailbreakBtn.didExpand)
        return;

    NSString *title = environmentUpdate ? DOLocalizedString(@"Button_Update_Environment") : DOLocalizedString(@"Button_Update_Available");
    
    NSString *releaseFrom = [[DOUIManager sharedInstance] getLaunchedReleaseTag];
    NSString *releaseTo = [[DOUIManager sharedInstance] getLatestReleaseTag];

    if (environmentUpdate)
    {
        releaseFrom = [[DOEnvironmentManager sharedManager] jailbrokenVersion];
        releaseTo = [[DOUIManager sharedInstance] getLaunchedReleaseTag];
    }

    self.updateButton = [DOActionMenuButton buttonWithAction:[UIAction actionWithTitle:title image:[UIImage systemImageNamed:@"arrow.down.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"update-available" handler:^(__kindof UIAction * _Nonnull action) {
        [self.navigationController pushViewController:[[DOUpdateViewController alloc] initFromTag:releaseFrom toTag:releaseTo] animated:YES];
    }] chevron:NO];

    self.updateButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.updateButton];

    [NSLayoutConstraint activateConstraints:@[
        [self.updateButton.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.updateButton.heightAnchor constraintEqualToConstant:30],
        [self.updateButton.bottomAnchor constraintEqualToAnchor:self.jailbreakBtn.topAnchor constant:[DOGlobalAppearance isHomeButtonDevice] ? -10 : -20]
    ]];

    [self.updateButton setTransform:CGAffineTransformMakeTranslation(0, 25)];
    [self.updateButton setAlpha:0];
    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0  options: UIViewAnimationOptionCurveEaseInOut animations:^{
        [self.updateButton setTransform:CGAffineTransformIdentity];
        [self.updateButton setAlpha:1];
    } completion:nil];
}

-(void)simulateJailbreak
{
    // Let's simulate a "jailbreak" using grand central dispatch

    DOUIManager *uiManager = [DOUIManager sharedInstance];

    static BOOL didFinish = NO; //not thread safe lol
    

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [uiManager completeJailbreak];
        [uiManager sendLog:@"Rebooting Userspace" debug: NO];
        didFinish = YES;
        [self fadeToBlack: ^{

        }];
    });

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [NSThread sleepForTimeInterval:0.2];
        [uiManager sendLog:@"Launching kexploitd" debug: NO];
        [NSThread sleepForTimeInterval:0.5];
        [uiManager sendLog:@"Launching oobPCI" debug: NO];
        [NSThread sleepForTimeInterval:0.15];
        [uiManager sendLog:@"Gaining r/w" debug: NO];
        [NSThread sleepForTimeInterval:0.8];
        [uiManager sendLog:@"Patchfinding" debug: NO];
        NSArray *types = @[@"AMFI", @"PAC", @"KTRR", @"KPP", @"PPL", @"KPF", @"APRR", @"AMCC", @"PAN", @"PXN", @"ASLR", @"OPA"]; //Ever heard of the legendary opa bypass
        while (true)
        {
            [NSThread sleepForTimeInterval:0.6 * rand() / RAND_MAX];
            if (didFinish) break;
            NSString *type = types[arc4random_uniform((uint32_t)types.count)];
            [uiManager sendLog:[NSString stringWithFormat:@"Bypassing %@", type] debug: NO];
        }
    });
}

- (void)fadeToBlack:(void (^)(void))completion
{
    static bool didFade = false;
    if (didFade)
        return;
    didFade = true;
    UIView *mainView = self.parentViewController.view;
    float deviceCornerRadius = [[[UIScreen mainScreen] valueForKey:@"_displayCornerRadius"] floatValue];

    mainView.layer.cornerRadius = deviceCornerRadius;
    mainView.layer.cornerCurve = kCACornerCurveContinuous;
    mainView.layer.masksToBounds = YES;
    
    self.hideStatusBar = YES;

    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0 options: UIViewAnimationOptionCurveEaseInOut animations:^{
        mainView.transform = CGAffineTransformMakeScale(0.9, 0.9);
        mainView.alpha = 0.0;
    } completion:^(BOOL success) {
        completion();
    }];
}

#pragma mark - Action Menu Delegate

- (BOOL)actionMenuShowsChevronForAction:(UIAction *)action
{
    if ([action.identifier isEqualToString:@"settings"] || [action.identifier isEqualToString:@"credits"]) return YES;
    return NO;
}

- (BOOL)actionMenuActionIsEnabled:(UIAction *)action
{
    if ([action.identifier isEqualToString:@"respring"] || [action.identifier isEqualToString:@"reboot-userspace"]) {
        return [[DOEnvironmentManager sharedManager] isJailbroken];
    }
    return YES;
}

#pragma mark - Status Bar

- (UIStatusBarStyle)preferredStatusBarStyle
{
    return UIStatusBarStyleLightContent;
}

- (BOOL)prefersStatusBarHidden
{
    return self.hideStatusBar;
}

- (BOOL)prefersHomeIndicatorAutoHidden
{
    return self.hideHomeIndicator;
}

- (void)setHideStatusBar:(BOOL)hideStatusBar
{
    _hideStatusBar = hideStatusBar;
    [self setNeedsStatusBarAppearanceUpdate];
}

- (void)setHideHomeIndicator:(BOOL)hideHomeIndicator
{
    _hideHomeIndicator = hideHomeIndicator;
    [self setNeedsUpdateOfHomeIndicatorAutoHidden];
}

@end
