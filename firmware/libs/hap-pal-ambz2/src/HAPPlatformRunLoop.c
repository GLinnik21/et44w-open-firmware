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


#include "HAPPlatform+Init.h"
#include "HAPPlatformRunLoop+Init.h"
#include "HAPPlatformRunLoop+Internal.h"

#include "FreeRTOS.h"
#include "queue.h"
#include "task.h"

static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "RunLoop" };

#define kCallbackQueueDepth 16

/** A scheduled callback; copied by value through the queue. */
typedef struct {
    HAPPlatformRunLoopCallback callback;
    uint8_t contextSize;
    HAP_ALIGNAS(8) uint8_t context[kHAPPlatformRunLoop_MaxCallbackContextBytes];
} Callback;

// Never freed: other tasks call ScheduleCallback at any time, so the handle must stay valid. Release only empties it.
static QueueHandle_t callbackQueue;
static bool isCreated;
static volatile bool isStopRequested;
static volatile bool isRunning;

void HAPPlatformRunLoopCreate(void) {
    HAPPrecondition(!isCreated);
    if (!callbackQueue) {
        callbackQueue = xQueueCreate(kCallbackQueueDepth, sizeof(Callback));
        if (!callbackQueue) {
            HAPLogError(&logObject, "Cannot create callback queue.");
            HAPFatalError();
        }
    }
    isCreated = true;
    isStopRequested = false;
    isRunning = false;
}

void HAPPlatformRunLoopRelease(void) {
    if (callbackQueue) {
        (void) xQueueReset(callbackQueue); // drops pending callbacks; safe against concurrent senders
    }
    isCreated = false;
    isRunning = false;
}

HAPError HAPPlatformRunLoopScheduleCallback(
        HAPPlatformRunLoopCallback callback,
        void* _Nullable const context,
        size_t contextSize) {
    HAPPrecondition(callback);
    HAPPrecondition(!contextSize || context);
    HAPPrecondition(callbackQueue);

    if (contextSize > kHAPPlatformRunLoop_MaxCallbackContextBytes) {
        HAPLogError(&logObject, "Callback context too large (%lu bytes).", (unsigned long) contextSize);
        return kHAPError_OutOfResources;
    }

    Callback item = { .callback = callback, .contextSize = (uint8_t) contextSize };
    if (contextSize) {
        HAPRawBufferCopyBytes(item.context, context, contextSize);
    }
    if (xQueueSend(callbackQueue, &item, 0) != pdTRUE) {
        HAPLogError(&logObject, "Callback queue full.");
        return kHAPError_OutOfResources;
    }
    return kHAPError_None;
}

/** Runs the callbacks that were queued when called (callbacks queueing more run next iteration). */
static void RunQueuedCallbacks(void) {
    Callback item;
    for (UBaseType_t n = uxQueueMessagesWaiting(callbackQueue); n > 0; n--) {
        if (xQueueReceive(callbackQueue, &item, 0) != pdTRUE) {
            break;
        }
        item.callback(item.contextSize ? item.context : NULL, item.contextSize);
    }
}

/** Milliseconds to sleep: until the next timer, at most kHAPPlatformRunLoop_MaxSleepMs. */
static uint32_t SleepMs(void) {
    uint32_t ms = kHAPPlatformRunLoop_MaxSleepMs;
    HAPTime deadline = HAPPlatformTimerNextDeadline();
    if (deadline) {
        HAPTime now = HAPPlatformClockGetCurrent();
        HAPTime delta = deadline > now ? deadline - now : 0;
        if (delta < ms) {
            ms = (uint32_t) delta;
        }
    }
    return ms;
}

/** Waits for socket events or the timeout. A queued callback ends the wait early when no sockets are watched. */
static void Wait(fd_set* readSet, fd_set* writeSet, fd_set* errorSet) {
    uint32_t ms = SleepMs();
    int maxFileDescriptor = HAPPlatformFileHandleCollect(readSet, writeSet, errorSet);

    if (maxFileDescriptor < 0) {
        // Nothing to select on: sleep on the queue so a new callback wakes us at once.
        Callback item;
        if (xQueuePeek(callbackQueue, &item, pdMS_TO_TICKS(ms)) != pdTRUE && ms > 0) {
            // Timed out (or woke early) - nothing else to do.
        }
        return;
    }

    struct timeval timeout = { .tv_sec = 0, .tv_usec = (suseconds_t) ms * 1000 };
    int e = select(maxFileDescriptor + 1, readSet, writeSet, errorSet, &timeout);
    if (e < 0) {
        HAPPlatformLogPOSIXError(kHAPLogType_Error, "select failed.", errno, __func__, HAP_FILE, __LINE__);
        HAPFatalError();
    }
    if (e == 0) {
        // Timed out: leave the sets clean for dispatch.
        FD_ZERO(readSet);
        FD_ZERO(writeSet);
        FD_ZERO(errorSet);
    }
}

void HAPPlatformRunLoopRun(void) {
    HAPPrecondition(callbackQueue);
    HAPPrecondition(!isRunning);

    HAPLogInfo(&logObject, "Entering run loop.");
    isRunning = true;
    isStopRequested = false;
    while (!isStopRequested) {
        fd_set readSet;
        fd_set writeSet;
        fd_set errorSet;
        FD_ZERO(&readSet);
        FD_ZERO(&writeSet);
        FD_ZERO(&errorSet);

        Wait(&readSet, &writeSet, &errorSet);

        RunQueuedCallbacks();
        HAPPlatformTimerFireExpired();
        HAPPlatformFileHandleDispatch(&readSet, &writeSet, &errorSet);
    }
    HAPLogInfo(&logObject, "Exiting run loop.");
    isRunning = false;
}

void HAPPlatformRunLoopStop(void) {
    if (isRunning) {
        isStopRequested = true;
    }
}
