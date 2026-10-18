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

// No NFC tag. The server is created without one (setupNFC == NULL), so the ADK never calls this; it
// exists because the ADK core references it.
#include "HAPPlatform+Init.h"

void HAPPlatformAccessorySetupNFCUpdateSetupPayload(
        HAPPlatformAccessorySetupNFCRef setupNFC HAP_UNUSED,
        const HAPSetupPayload* setupPayload HAP_UNUSED,
        bool isPairable HAP_UNUSED) {
    HAPFatalError();
}
