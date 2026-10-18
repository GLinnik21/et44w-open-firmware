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

// Private interface between the run loop and its file-handle / timer parts.
#ifndef HAP_PLATFORM_RUN_LOOP_INTERNAL_H
#define HAP_PLATFORM_RUN_LOOP_INTERNAL_H

#include <lwip/sockets.h>

#include "HAPPlatform.h"

/** Longest time (ms) the run loop sleeps, so that Stop() and queued callbacks are noticed promptly. */
#define kHAPPlatformRunLoop_MaxSleepMs 20

/**
 * Adds the descriptors of all registered file handles to the sets.
 *
 * @return Highest descriptor added, or -1 if none.
 */
int HAPPlatformFileHandleCollect(fd_set* readSet, fd_set* writeSet, fd_set* errorSet);

/** Invokes callbacks of file handles whose descriptors are set. Safe against reentrant (de)registration. */
void HAPPlatformFileHandleDispatch(fd_set* readSet, fd_set* writeSet, fd_set* errorSet);

/** Deadline of the earliest timer, or 0 if there is none. */
HAPTime HAPPlatformTimerNextDeadline(void);

/** Fires all timers whose deadline has passed. */
void HAPPlatformTimerFireExpired(void);

#endif
