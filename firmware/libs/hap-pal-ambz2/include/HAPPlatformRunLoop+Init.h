// Run loop: one FreeRTOS task runs HAPPlatformRunLoopRun(); it owns all HAP state.
// Other tasks talk to it only through HAPPlatformRunLoopScheduleCallback().
#ifndef HAP_PLATFORM_RUN_LOOP_INIT_H
#define HAP_PLATFORM_RUN_LOOP_INIT_H

#include "HAPPlatform.h"

/** Largest context HAPPlatformRunLoopScheduleCallback() accepts (it is copied into a queue). */
#define kHAPPlatformRunLoop_MaxCallbackContextBytes 32

/** Creates the run loop. Call once, before any other HAPPlatform* function that uses it. */
void HAPPlatformRunLoopCreate(void);

/** Drops pending callbacks. The callback queue itself is kept, since other tasks may still schedule into it. */
void HAPPlatformRunLoopRelease(void);

#endif
