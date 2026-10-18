// Derived from the HomeKit ADK Lightbulb example (Apache-2.0).
// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.
// Copyright 2020 Espressif Systems (Shanghai) PTE LTD (Apache-2.0).

// Pairing service (required by HAP; all handlers are in the ADK).
#include "hap_db.h"

// Pair Setup / Pair Verify: not readable or writable as plain characteristics, IP control points.
#define PAIRING_TLV(var, iidv, type, rd, wr) \
    static const HAPTLV8Characteristic var = { \
        .format = kHAPCharacteristicFormat_TLV8, \
        .iid = iidv, \
        .characteristicType = &kHAPCharacteristicType_##type, \
        .debugDescription = kHAPCharacteristicDebugDescription_##type, \
        .manufacturerDescription = NULL, \
        .properties = { .readable = false, \
                        .writable = false, \
                        .supportsEventNotification = false, \
                        .hidden = false, \
                        .requiresTimedWrite = false, \
                        .supportsAuthorizationData = false, \
                        .ip = { .controlPoint = true }, \
                        .ble = { .supportsBroadcastNotification = false, \
                                 .supportsDisconnectedNotification = false, \
                                 .readableWithoutSecurity = true, \
                                 .writableWithoutSecurity = true } }, \
        .callbacks = { .handleRead = rd, .handleWrite = wr } \
    }

PAIRING_TLV(pairSetupCharacteristic,
            kIID_PairingPairSetup,
            PairSetup,
            HAPHandlePairingPairSetupRead,
            HAPHandlePairingPairSetupWrite);
PAIRING_TLV(pairVerifyCharacteristic,
            kIID_PairingPairVerify,
            PairVerify,
            HAPHandlePairingPairVerifyRead,
            HAPHandlePairingPairVerifyWrite);

static const HAPUInt8Characteristic pairingFeaturesCharacteristic = {
    .format = kHAPCharacteristicFormat_UInt8,
    .iid = kIID_PairingPairingFeatures,
    .characteristicType = &kHAPCharacteristicType_PairingFeatures,
    .debugDescription = kHAPCharacteristicDebugDescription_PairingFeatures,
    .manufacturerDescription = NULL,
    .properties = { .readable = false,
                    .writable = false,
                    .supportsEventNotification = false,
                    .hidden = false,
                    .requiresTimedWrite = false,
                    .supportsAuthorizationData = false,
                    .ip = { .controlPoint = false, .supportsWriteResponse = false },
                    .ble = { .supportsDisconnectedNotification = false,
                             .supportsBroadcastNotification = false,
                             .readableWithoutSecurity = true,
                             .writableWithoutSecurity = false } },
    .units = kHAPCharacteristicUnits_None,
    .constraints = { .minimumValue = 0,
                     .maximumValue = UINT8_MAX,
                     .stepValue = 0,
                     .validValues = NULL,
                     .validValuesRanges = NULL },
    .callbacks = { .handleRead = HAPHandlePairingPairingFeaturesRead, .handleWrite = NULL }
};

static const HAPTLV8Characteristic pairingPairingsCharacteristic = {
    .format = kHAPCharacteristicFormat_TLV8,
    .iid = kIID_PairingPairingPairings,
    .characteristicType = &kHAPCharacteristicType_PairingPairings,
    .debugDescription = kHAPCharacteristicDebugDescription_PairingPairings,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS(true, true, false, true),
    .callbacks = { .handleRead = HAPHandlePairingPairingPairingsRead,
                   .handleWrite = HAPHandlePairingPairingPairingsWrite }
};

const HAPService pairingService = {
    .iid = kIID_Pairing,
    .serviceType = &kHAPServiceType_Pairing,
    .debugDescription = kHAPServiceDebugDescription_Pairing,
    .name = NULL,
    .properties = { .primaryService = false, .hidden = false, .ble = { .supportsConfiguration = false } },
    .linkedServices = NULL,
    .characteristics = (const HAPCharacteristic* const[]) { &pairSetupCharacteristic,
                                                            &pairVerifyCharacteristic,
                                                            &pairingFeaturesCharacteristic,
                                                            &pairingPairingsCharacteristic,
                                                            NULL }
};
