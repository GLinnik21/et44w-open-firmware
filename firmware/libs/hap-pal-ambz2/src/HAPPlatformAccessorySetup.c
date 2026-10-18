// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.
//
// Derived in structure from the Espressif ADK port (Apache-2.0).

#include "HAPPlatform+Init.h"
#include "HAPPlatformAccessorySetup+Init.h"

static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "AccessorySetup" };

void HAPPlatformAccessorySetupCreate(
        HAPPlatformAccessorySetupRef accessorySetup,
        const HAPPlatformAccessorySetupOptions* options) {
    HAPPrecondition(accessorySetup);
    HAPPrecondition(options);
    HAPPrecondition(options->setupInfo);

    HAPRawBufferZero(accessorySetup, sizeof *accessorySetup);
    accessorySetup->setupInfo = options->setupInfo;

    if (options->setupID) {
        HAPPrecondition(HAPStringGetNumBytes(options->setupID) == sizeof accessorySetup->setupID.stringValue - 1);
        HAPRawBufferCopyBytes(
                accessorySetup->setupID.stringValue, options->setupID, sizeof accessorySetup->setupID.stringValue);
        accessorySetup->hasSetupID = true;
    }
}

void HAPPlatformAccessorySetupLoadSetupInfo(HAPPlatformAccessorySetupRef accessorySetup, HAPSetupInfo* setupInfo) {
    HAPPrecondition(accessorySetup);
    HAPPrecondition(setupInfo);

    HAPRawBufferCopyBytes(setupInfo, accessorySetup->setupInfo, sizeof *setupInfo);
}

void HAPPlatformAccessorySetupLoadSetupCode(HAPPlatformAccessorySetupRef accessorySetup, HAPSetupCode* setupCode) {
    HAPPrecondition(accessorySetup);
    HAPPrecondition(setupCode);

    HAPLogError(&logObject, "The setup code is not stored on this accessory (no display).");
    HAPFatalError();
}

void HAPPlatformAccessorySetupLoadSetupID(
        HAPPlatformAccessorySetupRef accessorySetup,
        bool* valid,
        HAPSetupID* setupID) {
    HAPPrecondition(accessorySetup);
    HAPPrecondition(valid);
    HAPPrecondition(setupID);

    *valid = accessorySetup->hasSetupID;
    if (*valid) {
        HAPRawBufferCopyBytes(setupID, &accessorySetup->setupID, sizeof *setupID);
    }
}

//----------------------------------------------------------------------------------------------------------------------
// Deprecated APIs.

HAP_DEPRECATED_MSG("Return false and use HAPPlatformAccessorySetupDisplay / HAPPlatformAccessorySetupNFC instead.")
HAP_RESULT_USE_CHECK
HAPPlatformAccessorySetupCapabilities
        HAPPlatformAccessorySetupGetCapabilities(HAPPlatformAccessorySetupRef accessorySetup) {
    HAPPrecondition(accessorySetup);

    return (HAPPlatformAccessorySetupCapabilities) { .supportsDisplay = false, .supportsProgrammableNFC = false };
}

void HAPPlatformAccessorySetupUpdateSetupPayload(
        HAPPlatformAccessorySetupRef accessorySetup,
        const HAPSetupPayload* _Nullable setupPayload,
        const HAPSetupCode* _Nullable setupCode) {
    HAPPrecondition(accessorySetup);

    (void) setupPayload;
    (void) setupCode;
    HAPLogError(&logObject, "[NYI] %s.", __func__);
    HAPFatalError();
}
