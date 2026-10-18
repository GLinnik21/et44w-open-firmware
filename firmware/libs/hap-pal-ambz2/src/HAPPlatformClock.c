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

#include "FreeRTOS.h"
#include "task.h"

#include "HAPPlatform.h"

_Static_assert(configTICK_RATE_HZ == 1000, "one tick must be one millisecond");

// The tick counter is 32 bits and wraps after ~49 days; count the wraps.
HAPTime HAPPlatformClockGetCurrent(void) {
    static uint32_t previousTicks;
    static uint32_t numWraps;

    taskENTER_CRITICAL();
    uint32_t ticks = (uint32_t) xTaskGetTickCount();
    if (ticks < previousTicks) {
        numWraps++;
    }
    previousTicks = ticks;
    uint32_t wraps = numWraps;
    taskEXIT_CRITICAL();

    return ((HAPTime) wraps << 32) | ticks;
}
