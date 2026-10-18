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

#ifndef HAP_PLATFORM_IP_INIT_H
#define HAP_PLATFORM_IP_INIT_H

#ifdef __cplusplus
extern "C" {
#endif


#include "HAPPlatform.h"
#include "HAPPlatformFileHandle.h"

#if __has_feature(nullability)
#pragma clang assume_nonnull begin
#endif

/**@file
 * TCP stream manager on lwIP sockets (AmebaZ2).
 *
 * The listener is one AF_INET6 socket on in6addr_any, which lwIP makes dual-stack (IPv4 and IPv6). There is
 * no interface selection: the listener serves every interface.
 *
 * **Example**

   @code{.c}
   static HAPPlatformTCPStreamManager tcpStreamManager;

   HAPPlatformTCPStreamManagerCreate(&tcpStreamManager,
       &(const HAPPlatformTCPStreamManagerOptions) {
           .port = 8080,                  // or kHAPNetworkPort_Any for an ephemeral port
           .maxConcurrentTCPStreams = 9,  // the IP sessions served at once (lwipopts.h sizes the sockets)
   });

   @endcode
 */

/**
 * TCP stream manager initialization options.
 */
typedef struct {
    /**
     * Local port number on which to bind the TCP stream manager.
     *
     * - A value of kHAPNetworkPort_Any will use an unused port number from the ephemeral port range.
     */
    HAPNetworkPort port;

    /**
     * Maximum number of concurrent TCP streams.
     */
    size_t maxConcurrentTCPStreams;
} HAPPlatformTCPStreamManagerOptions;

// Opaque type. Do not use directly.
/**@cond */
typedef struct {
    HAPPlatformTCPStreamManagerRef tcpStreamManager;

    uint32_t interfaceIndex;
    HAPNetworkPort port;

    int fileDescriptor;
    HAPPlatformFileHandleRef fileHandle;
    HAPPlatformTCPStreamListenerCallback _Nullable callback;
    void* _Nullable context;
} HAPPlatformTCPStreamListener;
/**@endcond */

// Opaque type. Do not use directly.
/**@cond */
typedef struct {
    HAPPlatformTCPStreamManagerRef tcpStreamManager;

    int fileDescriptor;
    HAPPlatformFileHandleRef fileHandle;
    HAPPlatformTCPStreamEvent interests;
    HAPPlatformTCPStreamEventCallback _Nullable callback;
    void* _Nullable context;
} HAPPlatformTCPStream;
/**@endcond */

/**
 * TCP stream manager.
 */
struct HAPPlatformTCPStreamManager {
    // Opaque type. Do not access the instance fields directly.
    /**@cond */
    size_t numTCPStreams;
    size_t maxTCPStreams;

    struct {
        HAPNetworkPort port;
    } tcpStreamListenerConfiguration;

    HAPPlatformTCPStreamListener tcpStreamListener;
    HAPPlatformTCPStream* _Nullable tcpStreams;
    /**@endcond */
};

/**
 * Initializes TCP stream manager.
 *
 * @param[out] tcpStreamManager     Pointer to an allocated but uninitialized HAPPlatformTCPStreamManager structure.
 * @param      options              Initialization options.
 */
void HAPPlatformTCPStreamManagerCreate(
        HAPPlatformTCPStreamManagerRef tcpStreamManager,
        const HAPPlatformTCPStreamManagerOptions* options);

/**
 * Releases resources associated with an initialized TCP stream manager instance.
 *
 * - IMPORTANT: Do not use this method on TCP stream manager structures that are not initialized!
 *
 * @param      tcpStreamManager     TCP stream manager.
 */
void HAPPlatformTCPStreamManagerRelease(HAPPlatformTCPStreamManagerRef tcpStreamManager);

#if __has_feature(nullability)
#pragma clang assume_nonnull end
#endif

#ifdef __cplusplus
}
#endif

#endif
