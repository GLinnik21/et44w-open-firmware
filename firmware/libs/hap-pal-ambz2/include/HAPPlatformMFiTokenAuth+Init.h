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

// Software Token provider. This platform has no software token: it is never provisioned.
#ifndef HAP_PLATFORM_MFI_TOKEN_AUTH_INIT_H
#define HAP_PLATFORM_MFI_TOKEN_AUTH_INIT_H

#include "HAPPlatform.h"

typedef struct {
    HAPPlatformKeyValueStoreRef keyValueStore;
} HAPPlatformMFiTokenAuthOptions;

struct HAPPlatformMFiTokenAuth {
    HAPPlatformKeyValueStoreRef keyValueStore;
};

void HAPPlatformMFiTokenAuthCreate(
        HAPPlatformMFiTokenAuthRef mfiTokenAuth,
        const HAPPlatformMFiTokenAuthOptions* options);

bool HAPPlatformMFiTokenAuthIsProvisioned(HAPPlatformMFiTokenAuthRef mfiTokenAuth);

#endif
