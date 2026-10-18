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

#include <stdlib.h>

#include "HAPPlatform+Init.h"
#include "HAPPlatformRunLoop+Internal.h"
#include "HAPPlatformTimer.h"

static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "Timer" };

typedef struct HAPPlatformTimer HAPPlatformTimer;

struct HAPPlatformTimer {
    HAPTime deadline;
    HAPPlatformTimerCallback callback;
    void* _Nullable context;
    HAPPlatformTimer* _Nullable nextTimer;
};

// Singly-linked list ordered by deadline.
static HAPPlatformTimer* _Nullable timers;

HAP_RESULT_USE_CHECK
HAPError HAPPlatformTimerRegister(
        HAPPlatformTimerRef* timer_,
        HAPTime deadline,
        HAPPlatformTimerCallback callback,
        void* _Nullable context) {
    HAPPrecondition(timer_);
    HAPPrecondition(callback);

    HAPPlatformTimer* timer = calloc(1, sizeof(HAPPlatformTimer));
    if (!timer) {
        HAPLog(&logObject, "Cannot allocate more timers.");
        return kHAPError_OutOfResources;
    }
    timer->deadline = deadline ? deadline : 1; // 0 means "no timer" to the run loop.
    timer->callback = callback;
    timer->context = context;

    // '>' (not '>=') keeps timers with equal deadlines in registration order.
    HAPPlatformTimer* _Nullable* link = &timers;
    while (*link && (*link)->deadline <= timer->deadline) {
        link = &(*link)->nextTimer;
    }
    timer->nextTimer = *link;
    *link = timer;

    *timer_ = (HAPPlatformTimerRef) timer;
    return kHAPError_None;
}

void HAPPlatformTimerDeregister(HAPPlatformTimerRef timer_) {
    HAPPrecondition(timer_);
    HAPPlatformTimer* timer = (HAPPlatformTimer*) timer_;

    for (HAPPlatformTimer* _Nullable* link = &timers; *link; link = &(*link)->nextTimer) {
        if (*link == timer) {
            *link = timer->nextTimer;
            HAPPlatformFreeSafe(timer);
            return;
        }
    }
    HAPFatalError(); // Not registered.
}

HAPTime HAPPlatformTimerNextDeadline(void) {
    return timers ? timers->deadline : 0;
}

void HAPPlatformTimerFireExpired(void) {
    HAPTime now = HAPPlatformClockGetCurrent();

    while (timers && timers->deadline <= now) {
        // Unlink first so that reentrant register / deregister calls do not interfere.
        HAPPlatformTimer* expired = timers;
        timers = expired->nextTimer;

        expired->callback((HAPPlatformTimerRef) expired, expired->context);
        HAPPlatformFreeSafe(expired);
    }
}
