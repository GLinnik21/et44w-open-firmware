// Derived from the HomeKit ADK Lightbulb example (Apache-2.0).
// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.
// Copyright 2020 Espressif Systems (Shanghai) PTE LTD (Apache-2.0).

// Attribute database shared by all apps: the info, protocol and pairing services, their instance
// IDs (0x01-0x2F) and property helpers. App services use IIDs from HAP_DB_APP_IID_BASE up.
#ifndef HAP_DB_H
#define HAP_DB_H

#include "HAP.h"

#define kIID_AccessoryInformation                 ((uint64_t) 0x0001)
#define kIID_AccessoryInformationIdentify         ((uint64_t) 0x0002)
#define kIID_AccessoryInformationManufacturer     ((uint64_t) 0x0003)
#define kIID_AccessoryInformationModel            ((uint64_t) 0x0004)
#define kIID_AccessoryInformationName             ((uint64_t) 0x0005)
#define kIID_AccessoryInformationSerialNumber     ((uint64_t) 0x0006)
#define kIID_AccessoryInformationFirmwareRevision ((uint64_t) 0x0007)
#define kIID_AccessoryInformationHardwareRevision ((uint64_t) 0x0008)
#define kIID_AccessoryInformationADKVersion       ((uint64_t) 0x0009)

#define kIID_HAPProtocolInformation                 ((uint64_t) 0x0010)
#define kIID_HAPProtocolInformationServiceSignature ((uint64_t) 0x0011)
#define kIID_HAPProtocolInformationVersion          ((uint64_t) 0x0012)

#define kIID_Pairing                ((uint64_t) 0x0020)
#define kIID_PairingPairSetup       ((uint64_t) 0x0022)
#define kIID_PairingPairVerify      ((uint64_t) 0x0023)
#define kIID_PairingPairingFeatures ((uint64_t) 0x0024)
#define kIID_PairingPairingPairings ((uint64_t) 0x0025)

#define HAP_DB_APP_IID_BASE ((uint64_t) 0x0030)

/** Attributes (services + characteristics) of the three shared services: 9 info + 3 protocol + 5 pairing. */
#define HAP_DB_SHARED_ATTRIBUTES ((size_t) 17)

// Characteristic properties. The BLE fields stay false: this is an IP-only accessory.
#define DB_BLE_NONE \
    { .supportsBroadcastNotification = false, \
      .supportsDisconnectedNotification = false, \
      .readableWithoutSecurity = false, \
      .writableWithoutSecurity = false }

#define DB_PROPS(r, w, ev, cp) \
    { .readable = (r), \
      .writable = (w), \
      .supportsEventNotification = (ev), \
      .hidden = false, \
      .requiresTimedWrite = false, \
      .supportsAuthorizationData = false, \
      .ip = { .controlPoint = (cp), .supportsWriteResponse = false }, \
      .ble = DB_BLE_NONE }

/** Plain read-only characteristic. */
#define DB_PROPS_READ DB_PROPS(true, false, false, false)
/** Read-only IP control point (service signature). */
#define DB_PROPS_READ_CP DB_PROPS(true, false, false, true)

extern const HAPService accessoryInformationService;
extern const HAPService hapProtocolInformationService;
extern const HAPService pairingService;

#endif
