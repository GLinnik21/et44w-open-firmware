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
// limitations under the License.

// No Apple Authentication Coprocessor. The server is created without one (mfiHWAuth == NULL), so the
// ADK never reaches these; they exist because the ADK core references them.
#include "HAPPlatform+Init.h"

bool HAPPlatformMFiHWAuthIsPoweredOn(HAPPlatformMFiHWAuthRef mfiHWAuth HAP_UNUSED) {
    return false;
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformMFiHWAuthPowerOn(HAPPlatformMFiHWAuthRef mfiHWAuth HAP_UNUSED) {
    return kHAPError_Unknown;
}

void HAPPlatformMFiHWAuthPowerOff(HAPPlatformMFiHWAuthRef mfiHWAuth HAP_UNUSED) {
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformMFiHWAuthWrite(
        HAPPlatformMFiHWAuthRef mfiHWAuth HAP_UNUSED,
        const void* bytes HAP_UNUSED,
        size_t numBytes HAP_UNUSED) {
    return kHAPError_Unknown;
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformMFiHWAuthRead(
        HAPPlatformMFiHWAuthRef mfiHWAuth HAP_UNUSED,
        uint8_t registerAddress HAP_UNUSED,
        void* bytes HAP_UNUSED,
        size_t numBytes HAP_UNUSED) {
    return kHAPError_Unknown;
}
