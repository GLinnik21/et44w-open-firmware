// Derived from the HomeKit ADK Lightbulb example (Apache-2.0).
// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.
// Copyright 2020 Espressif Systems (Shanghai) PTE LTD (Apache-2.0).

// Accessory Information and HAP Protocol Information services.
#include "hap_db.h"

// All Accessory Information strings are read-only, max 64 characters, served by ADK handlers.
#define INFO_STRING(var, iidv, type, handler) \
    static const HAPStringCharacteristic var = { \
        .format = kHAPCharacteristicFormat_String, \
        .iid = iidv, \
        .characteristicType = &kHAPCharacteristicType_##type, \
        .debugDescription = kHAPCharacteristicDebugDescription_##type, \
        .manufacturerDescription = NULL, \
        .properties = DB_PROPS_READ, \
        .constraints = { .maxLength = 64 }, \
        .callbacks = { .handleRead = handler, .handleWrite = NULL } \
    }

static const HAPBoolCharacteristic identifyCharacteristic = {
    .format = kHAPCharacteristicFormat_Bool,
    .iid = kIID_AccessoryInformationIdentify,
    .characteristicType = &kHAPCharacteristicType_Identify,
    .debugDescription = kHAPCharacteristicDebugDescription_Identify,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS(false, true, false, false),
    .callbacks = { .handleRead = NULL, .handleWrite = HAPHandleAccessoryInformationIdentifyWrite }
};

INFO_STRING(manufacturerCharacteristic,
            kIID_AccessoryInformationManufacturer,
            Manufacturer,
            HAPHandleAccessoryInformationManufacturerRead);
INFO_STRING(modelCharacteristic, kIID_AccessoryInformationModel, Model, HAPHandleAccessoryInformationModelRead);
INFO_STRING(nameCharacteristic, kIID_AccessoryInformationName, Name, HAPHandleAccessoryInformationNameRead);
INFO_STRING(serialNumberCharacteristic,
            kIID_AccessoryInformationSerialNumber,
            SerialNumber,
            HAPHandleAccessoryInformationSerialNumberRead);
INFO_STRING(firmwareRevisionCharacteristic,
            kIID_AccessoryInformationFirmwareRevision,
            FirmwareRevision,
            HAPHandleAccessoryInformationFirmwareRevisionRead);
INFO_STRING(hardwareRevisionCharacteristic,
            kIID_AccessoryInformationHardwareRevision,
            HardwareRevision,
            HAPHandleAccessoryInformationHardwareRevisionRead);
INFO_STRING(adkVersionCharacteristic,
            kIID_AccessoryInformationADKVersion,
            ADKVersion,
            HAPHandleAccessoryInformationADKVersionRead);

const HAPService accessoryInformationService = {
    .iid = kIID_AccessoryInformation,
    .serviceType = &kHAPServiceType_AccessoryInformation,
    .debugDescription = kHAPServiceDebugDescription_AccessoryInformation,
    .name = NULL,
    .properties = { .primaryService = false, .hidden = false, .ble = { .supportsConfiguration = false } },
    .linkedServices = NULL,
    .characteristics = (const HAPCharacteristic* const[]) { &identifyCharacteristic,
                                                            &manufacturerCharacteristic,
                                                            &modelCharacteristic,
                                                            &nameCharacteristic,
                                                            &serialNumberCharacteristic,
                                                            &firmwareRevisionCharacteristic,
                                                            &hardwareRevisionCharacteristic,
                                                            &adkVersionCharacteristic,
                                                            NULL }
};

static const HAPDataCharacteristic protocolServiceSignatureCharacteristic = {
    .format = kHAPCharacteristicFormat_Data,
    .iid = kIID_HAPProtocolInformationServiceSignature,
    .characteristicType = &kHAPCharacteristicType_ServiceSignature,
    .debugDescription = kHAPCharacteristicDebugDescription_ServiceSignature,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS_READ_CP,
    .constraints = { .maxLength = 2097152 },
    .callbacks = { .handleRead = HAPHandleServiceSignatureRead, .handleWrite = NULL }
};

INFO_STRING(protocolVersionCharacteristic,
            kIID_HAPProtocolInformationVersion,
            Version,
            HAPHandleHAPProtocolInformationVersionRead);

const HAPService hapProtocolInformationService = {
    .iid = kIID_HAPProtocolInformation,
    .serviceType = &kHAPServiceType_HAPProtocolInformation,
    .debugDescription = kHAPServiceDebugDescription_HAPProtocolInformation,
    .name = NULL,
    .properties = { .primaryService = false, .hidden = false, .ble = { .supportsConfiguration = true } },
    .linkedServices = NULL,
    .characteristics = (const HAPCharacteristic* const[]) { &protocolServiceSignatureCharacteristic,
                                                            &protocolVersionCharacteristic,
                                                            NULL }
};
