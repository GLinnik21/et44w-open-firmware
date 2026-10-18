// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.
//
// Derived from the Espressif ADK port (Copyright 2020 Espressif Systems (Shanghai) PTE LTD, Apache-2.0).

#ifndef HAP_PLATFORM_SERVICE_DISCOVERY_INIT_H
#define HAP_PLATFORM_SERVICE_DISCOVERY_INIT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#include "HAPPlatform.h"

#if __has_feature(nullability)
#pragma clang assume_nonnull begin
#endif

/**@file
 * Bonjour service discovery on lwIP's own mDNS responder (`lwip/src/apps/mdns/mdns.c`), IPv4 and IPv6.
 *
 * - The responder runs in the tcpip thread. All lwIP calls are made from there through `tcpip_callback`, with the
 *   arguments copied, so every function here may be called from the HAP run-loop task and returns immediately.
 *   Errors in the tcpip thread are logged, not returned.
 * - The responder only announces (no probing, no conflict renaming, no goodbye packets): pick a unique name.
 * - Call HAPPlatformServiceDiscoveryNetworkChanged after the Wi-Fi link comes back or the IP address changes.
 * - Only one service is supported (the HAP `_hap._tcp` record).
 */

struct netif;

/**
 * Service discovery initialization options.
 */
typedef struct {
    /**
     * Host name for `<hostName>.local`, at most 63 characters. NULL means "hap-" + the last three MAC bytes
     * (e.g. "hap-a1b2c3"), so several accessories on one link don't claim the same host name.
     */
    const char* _Nullable hostName;

    /**
     * Network interface to publish on. NULL means the SDK's station interface `xnetif[0]`.
     */
    struct netif* _Nullable netif;
} HAPPlatformServiceDiscoveryOptions;

/** Largest TXT record set (sum of 1 + strlen("key=value") over all items) that is accepted. */
#define kHAPPlatformServiceDiscovery_MaxTXTSize 250

/**@cond */
// Registered service. Owned by the tcpip thread once service discovery is created.
typedef struct {
    char name[64];
    char type[32]; // "_hap"
    HAPNetworkPort port;
    uint8_t txt[kHAPPlatformServiceDiscovery_MaxTXTSize]; // Items, each prefixed with its length.
    size_t txtSize;
} HAPPlatformServiceDiscoveryService;
/**@endcond */

/**
 * Service discovery.
 */
struct HAPPlatformServiceDiscovery {
    // Opaque type. Do not access the instance fields directly.
    /**@cond */
    struct netif* _Nullable netif;
    char hostName[64];
    bool registered; // Touched by the tcpip thread only.
    HAPPlatformServiceDiscoveryService service;
    /**@endcond */
};

/**
 * Initializes service discovery. Does not touch the network yet. The structure must stay allocated (static).
 *
 * @param[out] serviceDiscovery     Pointer to an allocated but uninitialized HAPPlatformServiceDiscovery structure.
 * @param      options              Initialization options.
 */
void HAPPlatformServiceDiscoveryCreate(
        HAPPlatformServiceDiscoveryRef serviceDiscovery,
        const HAPPlatformServiceDiscoveryOptions* options);

/**
 * Restarts the responder on the interface (rejoins the multicast groups) and announces again. Call after Wi-Fi
 * reconnects or the IP address changes. Does nothing if no service is registered.
 *
 * @param      serviceDiscovery     Service discovery.
 */
void HAPPlatformServiceDiscoveryNetworkChanged(HAPPlatformServiceDiscoveryRef serviceDiscovery);

#if __has_feature(nullability)
#pragma clang assume_nonnull end
#endif

#ifdef __cplusplus
}
#endif

#endif
