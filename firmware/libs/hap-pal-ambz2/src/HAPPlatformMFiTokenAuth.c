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

// No software token is ever provisioned on this platform.
#include "HAPPlatform+Init.h"
#include "HAPPlatformMFiTokenAuth+Init.h"

void HAPPlatformMFiTokenAuthCreate(
        HAPPlatformMFiTokenAuthRef mfiTokenAuth,
        const HAPPlatformMFiTokenAuthOptions* options) {
    HAPPrecondition(mfiTokenAuth);
    HAPPrecondition(options);
    HAPPrecondition(options->keyValueStore);

    mfiTokenAuth->keyValueStore = options->keyValueStore;
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformMFiTokenAuthLoad(
        HAPPlatformMFiTokenAuthRef mfiTokenAuth,
        bool* valid,
        HAPPlatformMFiTokenAuthUUID* _Nullable mfiTokenUUID HAP_UNUSED,
        void* _Nullable mfiTokenBytes HAP_UNUSED,
        size_t maxMFiTokenBytes HAP_UNUSED,
        size_t* _Nullable numMFiTokenBytes) {
    HAPPrecondition(mfiTokenAuth);
    HAPPrecondition(valid);

    *valid = false;
    if (numMFiTokenBytes) {
        *numMFiTokenBytes = 0;
    }
    return kHAPError_None;
}

bool HAPPlatformMFiTokenAuthIsProvisioned(HAPPlatformMFiTokenAuthRef mfiTokenAuth) {
    HAPPrecondition(mfiTokenAuth);
    return false;
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformMFiTokenAuthUpdate(
        HAPPlatformMFiTokenAuthRef mfiTokenAuth,
        const void* mfiTokenBytes HAP_UNUSED,
        size_t numMFiTokenBytes HAP_UNUSED) {
    HAPPrecondition(mfiTokenAuth);
    return kHAPError_Unknown; // nothing provisioned to update
}
