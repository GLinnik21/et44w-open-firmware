// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.
//
// Derived from the Espressif ADK port (Copyright 2020 Espressif Systems (Shanghai) PTE LTD, Apache-2.0).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "HAPPlatform+Init.h"
#include "HAPPlatformServiceDiscovery+Init.h"

#include "FreeRTOS.h"
#include "lwip/apps/mdns.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"

extern struct netif xnetif[];

static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "ServiceDiscovery" };

#define kDefaultHostNamePrefix "hap-" // + last three MAC bytes in hex.
#define kDNSTTL                120 // Seconds.

typedef enum { kOp_Register, kOp_UpdateTXT, kOp_Stop, kOp_Restart } Op;

/** Work item for the tcpip thread. Freed there. */
typedef struct {
    HAPPlatformServiceDiscoveryRef sd;
    Op op;
    HAPPlatformServiceDiscoveryService service; // Register and UpdateTXT.
} Message;

// ---- Runs in the tcpip thread only ----

/** lwIP callback: appends the stored TXT items to a reply. */
static void GetTXT(struct mdns_service* mdnsService, void* userdata) {
    const HAPPlatformServiceDiscovery* sd = userdata;
    for (size_t i = 0; i < sd->service.txtSize;) {
        uint8_t length = sd->service.txt[i];
        if (mdns_resp_add_service_txtitem(mdnsService, (const char*) &sd->service.txt[i + 1], length) != ERR_OK) {
            return;
        }
        i += 1 + (size_t) length;
    }
}

static void StartResponder(HAPPlatformServiceDiscovery* sd) {
    static bool initialized;
    if (!initialized) {
        mdns_resp_init();
        initialized = true;
    }

    // Joining multicast groups requires these flags (the SDK's own mDNS port sets IGMP the same way).
    sd->netif->flags |= NETIF_FLAG_IGMP;
#if LWIP_IPV6
    sd->netif->flags |= NETIF_FLAG_MLD6;
#endif

    if (!sd->hostName[0]) {
        const uint8_t* mac = sd->netif->hwaddr;
        snprintf(sd->hostName, sizeof sd->hostName, kDefaultHostNamePrefix "%02x%02x%02x", mac[3], mac[4], mac[5]);
    }
    err_t err = mdns_resp_add_netif(sd->netif, sd->hostName, kDNSTTL);
    if (err == ERR_OK) {
        err = mdns_resp_add_service(
                sd->netif, sd->service.name, sd->service.type, DNSSD_PROTO_TCP, sd->service.port, kDNSTTL, GetTXT, sd);
        if (err != ERR_OK) {
            mdns_resp_remove_netif(sd->netif);
        }
    }
    sd->registered = err == ERR_OK;
    if (err != ERR_OK) {
        HAPLogError(&logObject, "Starting the mDNS responder failed: lwIP error %d.", (int) err);
    }
}

static void StopResponder(HAPPlatformServiceDiscovery* sd) {
    if (sd->registered) {
        mdns_resp_remove_netif(sd->netif);
        sd->registered = false;
    }
}

static void RunMessage(void* context) {
    Message* message = context;
    HAPPlatformServiceDiscovery* sd = message->sd;

    switch (message->op) {
        case kOp_Register:
            StopResponder(sd);
            sd->service = message->service;
            StartResponder(sd);
            break;
        case kOp_UpdateTXT:
            memcpy(sd->service.txt, message->service.txt, message->service.txtSize);
            sd->service.txtSize = message->service.txtSize;
            if (sd->registered) {
                mdns_resp_netif_settings_changed(sd->netif); // Announces the new TXT data.
            }
            break;
        case kOp_Stop:
            StopResponder(sd);
            break;
        case kOp_Restart:
            if (sd->registered) {
                StopResponder(sd);
                StartResponder(sd);
            }
            break;
    }
    free(message);
}

// ---- Callable from any task ----

static void Post(Message* message) {
    if (tcpip_callback(RunMessage, message) != ERR_OK) {
        HAPLogError(&logObject, "Posting to the tcpip thread failed: out of memory.");
        HAPFatalError();
    }
}

static Message* NewMessage(HAPPlatformServiceDiscoveryRef sd, Op op) {
    Message* message = calloc(1, sizeof *message);
    if (!message) {
        HAPLogError(&logObject, "Out of memory.");
        HAPFatalError();
    }
    message->sd = sd;
    message->op = op;
    return message;
}

/** Packs "key=value" items, each prefixed with its length, as mdns_resp_add_service_txtitem wants them. */
static void PackTXT(
        HAPPlatformServiceDiscoveryService* service,
        const HAPPlatformServiceDiscoveryTXTRecord* txtRecords,
        size_t numTXTRecords) {
    size_t size = 0;
    for (size_t i = 0; i < numTXTRecords; i++) {
        HAPPrecondition(!txtRecords[i].value.numBytes || txtRecords[i].value.bytes);
        size_t keyLength = strlen(txtRecords[i].key);
        size_t itemLength = keyLength + 1 + txtRecords[i].value.numBytes;
        HAPPrecondition(itemLength <= UINT8_MAX);
        HAPPrecondition(size + 1 + itemLength <= sizeof service->txt);
        service->txt[size++] = (uint8_t) itemLength;
        memcpy(&service->txt[size], txtRecords[i].key, keyLength);
        size += keyLength;
        service->txt[size++] = '=';
        if (txtRecords[i].value.numBytes) {
            memcpy(&service->txt[size], txtRecords[i].value.bytes, txtRecords[i].value.numBytes);
            size += txtRecords[i].value.numBytes;
        }
    }
    service->txtSize = size;
}

void HAPPlatformServiceDiscoveryCreate(
        HAPPlatformServiceDiscoveryRef serviceDiscovery,
        const HAPPlatformServiceDiscoveryOptions* options) {
    HAPPrecondition(serviceDiscovery);
    HAPPrecondition(options);

    HAPPrecondition(!options->hostName || strlen(options->hostName) <= MDNS_LABEL_MAXLEN);

    HAPRawBufferZero(serviceDiscovery, sizeof *serviceDiscovery);
    serviceDiscovery->netif = options->netif ? options->netif : &xnetif[0];
    if (options->hostName) {
        strcpy(serviceDiscovery->hostName, options->hostName);
    } // Else left empty: StartResponder derives it from the MAC, which the netif only has once Wi-Fi is up.
}

void HAPPlatformServiceDiscoveryRegister(
        HAPPlatformServiceDiscoveryRef serviceDiscovery,
        const char* name,
        const char* protocol,
        HAPNetworkPort port,
        HAPPlatformServiceDiscoveryTXTRecord* txtRecords,
        size_t numTXTRecords) {
    HAPPrecondition(serviceDiscovery);
    HAPPrecondition(name);
    HAPPrecondition(protocol);
    HAPPrecondition(txtRecords);

    // Only "<type>._tcp" is supported (HAP uses "_hap._tcp").
    static const char suffix[] = "._tcp";
    size_t protocolLength = strlen(protocol);
    HAPPrecondition(protocolLength > sizeof suffix - 1 && !strcmp(protocol + protocolLength - (sizeof suffix - 1), suffix));
    size_t typeLength = protocolLength - (sizeof suffix - 1);

    Message* message = NewMessage(serviceDiscovery, kOp_Register);
    HAPPrecondition(strlen(name) < sizeof message->service.name);
    HAPPrecondition(typeLength < sizeof message->service.type);
    strcpy(message->service.name, name);
    memcpy(message->service.type, protocol, typeLength);
    message->service.port = port;
    PackTXT(&message->service, txtRecords, numTXTRecords);
    Post(message);
}

void HAPPlatformServiceDiscoveryUpdateTXTRecords(
        HAPPlatformServiceDiscoveryRef serviceDiscovery,
        HAPPlatformServiceDiscoveryTXTRecord* txtRecords,
        size_t numTXTRecords) {
    HAPPrecondition(serviceDiscovery);
    HAPPrecondition(txtRecords);

    Message* message = NewMessage(serviceDiscovery, kOp_UpdateTXT);
    PackTXT(&message->service, txtRecords, numTXTRecords);
    Post(message);
}

void HAPPlatformServiceDiscoveryStop(HAPPlatformServiceDiscoveryRef serviceDiscovery) {
    HAPPrecondition(serviceDiscovery);
    Post(NewMessage(serviceDiscovery, kOp_Stop));
}

void HAPPlatformServiceDiscoveryNetworkChanged(HAPPlatformServiceDiscoveryRef serviceDiscovery) {
    HAPPrecondition(serviceDiscovery);
    Post(NewMessage(serviceDiscovery, kOp_Restart));
}
