#pragma once

#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdbool.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, PLRuntimeState) {
    PLRuntimeStateCold = 0,
    PLRuntimeStateTargetValidated,
    PLRuntimeStateKernelEntryReady,
    PLRuntimeStateKernelSessionVerified,
    PLRuntimeStatePatchPlanReady,
    PLRuntimeStateBootstrapStaged,
    PLRuntimeStateBootstrapVerified,
    PLRuntimeStateActivationReady,
    PLRuntimeStateActive,
    PLRuntimeStateSafeMode,
    PLRuntimeStateReverting,
    PLRuntimeStateReverted,
    PLRuntimeStateFailed,
};

typedef NS_ENUM(NSInteger, PLRuntimeErrorCode) {
    PLRuntimeErrorInvalidTransition = 1000,
    PLRuntimeErrorKernelProviderMissing,
    PLRuntimeErrorKernelSessionInvalid,
    PLRuntimeErrorKernelIdentityMismatch,
    PLRuntimeErrorPatchPlanInvalid,
    PLRuntimeErrorPatchBytesMismatch,
    PLRuntimeErrorBootstrapManifestInvalid,
    PLRuntimeErrorBootstrapTransactionIncomplete,
    PLRuntimeErrorActivationNotArmed,
    PLRuntimeErrorRecoveryRequired,
};

typedef NS_OPTIONS(uint64_t, PLKernelCapability) {
    PLKernelCapabilityNone             = 0,
    PLKernelCapabilityRead             = 1ull << 0,
    PLKernelCapabilityWrite            = 1ull << 1,
    PLKernelCapabilityPhysicalRead     = 1ull << 2,
    PLKernelCapabilityPhysicalWrite    = 1ull << 3,
    PLKernelCapabilityTrustCache       = 1ull << 4,
    PLKernelCapabilityProcessMutation  = 1ull << 5,
    PLKernelCapabilityLaunchdHandoff   = 1ull << 6,
};

typedef struct {
    uint64_t kernelBase;
    uint64_t kernelSlide;
    uint32_t pageSize;
    PLKernelCapability capabilities;
    const char *providerName;
    const char *providerVersion;
} PLKernelSessionDescriptor;

static inline NSString *PLRuntimeStateName(PLRuntimeState state)
{
    switch (state) {
        case PLRuntimeStateCold: return @"cold";
        case PLRuntimeStateTargetValidated: return @"target-validated";
        case PLRuntimeStateKernelEntryReady: return @"kernel-entry-ready";
        case PLRuntimeStateKernelSessionVerified: return @"kernel-session-verified";
        case PLRuntimeStatePatchPlanReady: return @"patch-plan-ready";
        case PLRuntimeStateBootstrapStaged: return @"bootstrap-staged";
        case PLRuntimeStateBootstrapVerified: return @"bootstrap-verified";
        case PLRuntimeStateActivationReady: return @"activation-ready";
        case PLRuntimeStateActive: return @"active";
        case PLRuntimeStateSafeMode: return @"safe-mode";
        case PLRuntimeStateReverting: return @"reverting";
        case PLRuntimeStateReverted: return @"reverted";
        case PLRuntimeStateFailed: return @"failed";
    }
}

static inline NSError *PLRuntimeError(PLRuntimeErrorCode code, NSString *message)
{
    return [NSError errorWithDomain:@"com.nightvibes33.paleramine.runtime"
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message ?: @"Paleramine runtime error"}];
}

NS_ASSUME_NONNULL_END
