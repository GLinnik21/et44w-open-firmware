// HomeKit ADK platform abstraction layer for Realtek AmebaZ2 (RTL8710C/RTL8720C): common definitions.
#ifndef HAP_PLATFORM_INIT_H
#define HAP_PLATFORM_INIT_H

// Optional ADK features this platform does not have.
#define HAVE_DISPLAY     0
#define HAVE_NFC         0
#define HAVE_MFI_HW_AUTH 0

#include <stdlib.h>

#include "HAPPlatform.h"

// IP session storage. HAP requires 8 concurrent controller connections, plus one to refuse the 9th.
#define kHAPIPSessionStorage_MinimumNumElements 9
#define kHAPIPSession_MinimumInboundBufferSize  1024
#define kHAPIPSession_MinimumOutboundBufferSize 1536
#define kHAPIPSession_MinimumScratchBufferSize  1536

/** Frees ptr (allocated with malloc/calloc) and sets it to NULL. */
#define HAPPlatformFreeSafe(ptr) \
    do { \
        HAPAssert(ptr); \
        free(ptr); \
        ptr = NULL; \
    } while (0)

/** Logs a failed lwIP/POSIX call with its errno. */
void HAPPlatformLogPOSIXError(
        HAPLogType type,
        const char* message,
        int errorNumber,
        const char* function,
        const char* file,
        int line);

#endif
