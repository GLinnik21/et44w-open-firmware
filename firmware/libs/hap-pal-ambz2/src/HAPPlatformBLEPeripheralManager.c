// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.
//
// Copyright 2020 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

// No BLE. The ADK core references the BLE peripheral manager, but a BLE transport is never started,
// so none of these is called (SetDelegate/Remove/Cancel are harmless no-ops, the rest are fatal).
#include "HAPPlatform+Init.h"

#define U HAP_UNUSED

void HAPPlatformBLEPeripheralManagerSetDelegate(
        HAPPlatformBLEPeripheralManagerRef m U, const HAPPlatformBLEPeripheralManagerDelegate* _Nullable d U) {
}

void HAPPlatformBLEPeripheralManagerSetDeviceAddress(
        HAPPlatformBLEPeripheralManagerRef m U, const HAPPlatformBLEPeripheralManagerDeviceAddress* a U) {
    HAPFatalError();
}

void HAPPlatformBLEPeripheralManagerSetDeviceName(HAPPlatformBLEPeripheralManagerRef m U, const char* n U) {
    HAPFatalError();
}

void HAPPlatformBLEPeripheralManagerRemoveAllServices(HAPPlatformBLEPeripheralManagerRef m U) {
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformBLEPeripheralManagerAddService(
        HAPPlatformBLEPeripheralManagerRef m U, const HAPPlatformBLEPeripheralManagerUUID* t U, bool p U) {
    HAPFatalError();
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformBLEPeripheralManagerAddCharacteristic(
        HAPPlatformBLEPeripheralManagerRef m U,
        const HAPPlatformBLEPeripheralManagerUUID* t U,
        HAPPlatformBLEPeripheralManagerCharacteristicProperties p U,
        const void* _Nullable b U,
        size_t n U,
        HAPPlatformBLEPeripheralManagerAttributeHandle* v U,
        HAPPlatformBLEPeripheralManagerAttributeHandle* _Nullable c U) {
    HAPFatalError();
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformBLEPeripheralManagerAddDescriptor(
        HAPPlatformBLEPeripheralManagerRef m U,
        const HAPPlatformBLEPeripheralManagerUUID* t U,
        HAPPlatformBLEPeripheralManagerDescriptorProperties p U,
        const void* _Nullable b U,
        size_t n U,
        HAPPlatformBLEPeripheralManagerAttributeHandle* d U) {
    HAPFatalError();
}

void HAPPlatformBLEPeripheralManagerPublishServices(HAPPlatformBLEPeripheralManagerRef m U) {
    HAPFatalError();
}

void HAPPlatformBLEPeripheralManagerStartAdvertising(
        HAPPlatformBLEPeripheralManagerRef m U,
        HAPBLEAdvertisingInterval i U,
        const void* a U,
        size_t an U,
        const void* _Nullable s U,
        size_t sn U) {
    HAPFatalError();
}

void HAPPlatformBLEPeripheralManagerStopAdvertising(HAPPlatformBLEPeripheralManagerRef m U) {
}

void HAPPlatformBLEPeripheralManagerCancelCentralConnection(
        HAPPlatformBLEPeripheralManagerRef m U, HAPPlatformBLEPeripheralManagerConnectionHandle h U) {
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformBLEPeripheralManagerSendHandleValueIndication(
        HAPPlatformBLEPeripheralManagerRef m U,
        HAPPlatformBLEPeripheralManagerConnectionHandle c U,
        HAPPlatformBLEPeripheralManagerAttributeHandle v U,
        const void* _Nullable b U,
        size_t n U) {
    HAPFatalError();
}
