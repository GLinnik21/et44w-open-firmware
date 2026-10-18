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

// No setup display. The server is created without one (setupDisplay == NULL), so the ADK never calls
// these; they exist because the ADK core references them.
#include "HAPPlatform+Init.h"

void HAPPlatformAccessorySetupDisplayUpdateSetupPayload(
        HAPPlatformAccessorySetupDisplayRef setupDisplay HAP_UNUSED,
        const HAPSetupPayload* _Nullable setupPayload HAP_UNUSED,
        const HAPSetupCode* _Nullable setupCode HAP_UNUSED) {
    HAPFatalError();
}

void HAPPlatformAccessorySetupDisplayHandleStartPairing(HAPPlatformAccessorySetupDisplayRef setupDisplay HAP_UNUSED) {
    HAPFatalError();
}

void HAPPlatformAccessorySetupDisplayHandleStopPairing(HAPPlatformAccessorySetupDisplayRef setupDisplay HAP_UNUSED) {
    HAPFatalError();
}
