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

// Logging to the console UART. Never enables sensitive output; the level comes from HAP_LOG_LEVEL.
#include "HAPPlatform+Init.h"
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"


static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "Log" };

void HAPPlatformLogPOSIXError(
        HAPLogType type,
        const char* _Nonnull message,
        int errorNumber,
        const char* _Nonnull function,
        const char* _Nonnull file,
        int line) {
    HAPPrecondition(message);
    HAPPrecondition(function);
    HAPPrecondition(file);

    HAPLogWithType(
            &logObject, type, "%s:%d:%s - %s @ %s:%d", message, errorNumber, strerror(errorNumber), function, file, line);
}

/**
 * At level 2, the "Characteristic" category logs a line per characteristic on every controller read or write
 * (~2 KiB per Home app refresh), which would flush the small console history (netlog ring) of everything else.
 */
static bool IsChatty(const HAPLogObject* log) {
    return log->category && !strcmp(log->category, "Characteristic");
}

HAP_RESULT_USE_CHECK
HAPPlatformLogEnabledTypes HAPPlatformLogGetEnabledTypes(const HAPLogObject* _Nonnull log) {
    switch (HAP_LOG_LEVEL) {
        case 0: {
            return kHAPPlatformLogEnabledTypes_None;
        }
        case 1: {
            return kHAPPlatformLogEnabledTypes_Default;
        }
        case 2: {
            return IsChatty(log) ? kHAPPlatformLogEnabledTypes_Default : kHAPPlatformLogEnabledTypes_Info;
        }
        case 3: {
            return kHAPPlatformLogEnabledTypes_Debug;
        }
        default: {
            HAPFatalError();
        }
    }
}

static const char* TypeName(HAPLogType type) {
    switch (type) {
        case kHAPLogType_Debug: return "Debug";
        case kHAPLogType_Info: return "Info";
        case kHAPLogType_Default: return "Default";
        case kHAPLogType_Error: return "Error";
        case kHAPLogType_Fault: return "Fault";
    }
    return "?";
}

/** Prints the buffer as hex, 16 bytes per line. */
static void PrintBuffer(const uint8_t* bytes, size_t numBytes) {
    for (size_t i = 0; i < numBytes; i += 16) {
        char line[16 * 2 + 1];
        size_t n = numBytes - i < 16 ? numBytes - i : 16;
        for (size_t j = 0; j < n; j++) {
            snprintf(&line[j * 2], 3, "%02x", bytes[i + j]);
        }
        printf("    %04x %s\n", (unsigned) i, line);
    }
}

void HAPPlatformLogCapture(
        const HAPLogObject* _Nonnull log,
        HAPLogType type,
        const char* _Nonnull message,
        const void* _Nullable bufferBytes,
        size_t numBufferBytes) HAP_DIAGNOSE_ERROR(!bufferBytes && numBufferBytes, "empty buffer cannot have a length") {
    HAPPrecondition(log);
    HAPPrecondition(message);
    HAPPrecondition(!numBufferBytes || bufferBytes);

    // One printf per line keeps lines of different tasks from interleaving mid-line.
    printf("%lu\t%s\t[%s:%s] %s\n",
           (unsigned long) xTaskGetTickCount(),
           TypeName(type),
           log->subsystem ? log->subsystem : "",
           log->category ? log->category : "",
           message);
    if (bufferBytes) {
        PrintBuffer(bufferBytes, numBufferBytes);
    }
}
