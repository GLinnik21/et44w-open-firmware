// Derived from the HomeKit ADK Lightbulb example (Apache-2.0); see hap_db.h for the license header.
// HAP headers first: SDK libc headers included earlier break HAPBase.h.
#include "HAP.h"
#include "HAPPlatform+Init.h"
#include "HAPPlatformAccessorySetup+Init.h"
#include "HAPPlatformKeyValueStore+Init.h"
#include "HAPPlatformMFiTokenAuth+Init.h"
#include "HAPPlatformRandomNumber+Init.h"
#include "HAPPlatformRunLoop+Init.h"
#include "HAPPlatformServiceDiscovery+Init.h"
#include "HAPPlatformTCPStreamManager+Init.h"

#include "FreeRTOS.h"
#include "flash_map.h"
#include "semphr.h"
#include "task.h"

#include "hap_app.h"

// Measured peak ~1160 words (ET-44W, 2026-10-17, through a full SRP-3072 pair setup and several
// controller sessions); 3072 words = 12 KiB leaves ~2.6x. netlog prints the high-water mark.
#define HAP_TASK_STACK_WORDS 3072
#define HAP_TASK_PRIORITY    (tskIDLE_PRIORITY + 4)
#define HAP_TCP_PORT         ((HAPNetworkPort) 8080)
#define NETWORK_UP_RETRY_MS  100

static struct {
    HAPPlatformKeyValueStore keyValueStore;
    HAPPlatformAccessorySetup accessorySetup;
    HAPPlatformTCPStreamManager tcpStreamManager;
    HAPPlatformServiceDiscovery serviceDiscovery;
    HAPPlatformMFiTokenAuth mfiTokenAuth;
    HAPPlatform hapPlatform;
    HAPAccessoryServerOptions serverOptions;
    HAPAccessoryServerCallbacks serverCallbacks;
    HAPAccessoryServerRef server;
} p;

static SemaphoreHandle_t ready_sem; // given once the run loop exists
static const hap_app_config* cfg;

static void handle_updated_state(HAPAccessoryServerRef* server, void* _Nullable context HAP_UNUSED) {
    switch (HAPAccessoryServerGetState(server)) {
        case kHAPAccessoryServerState_Idle: HAPLogInfo(&kHAPLog_Default, "Server: idle"); break;
        case kHAPAccessoryServerState_Running:
            HAPLogInfo(&kHAPLog_Default, "Server: running");
            if (cfg->onRunning) {
                cfg->onRunning();
            }
            break;
        case kHAPAccessoryServerState_Stopping: HAPLogInfo(&kHAPLog_Default, "Server: stopping"); break;
    }
}

// Runs on the HAP task (via the run loop). Later network-up events while running are no-ops: the
// PAL's sockets and service discovery keep working across a re-association.
static void on_network_up(void* _Nullable context HAP_UNUSED, size_t contextSize HAP_UNUSED) {
    if (HAPAccessoryServerGetState(&p.server) == kHAPAccessoryServerState_Idle) {
        HAPAccessoryServerStart(&p.server, cfg->accessory);
    }
}

static void init_platform(void) {
    HAPPlatformRunLoopCreate();
    // mfiHWAuth, setupDisplay, setupNFC stay NULL (static zero-init).

    HAPPlatformKeyValueStoreCreate(&p.keyValueStore, &(const HAPPlatformKeyValueStoreOptions) { .baseAddress = FLASH_kv_OFFSET,
                                                        .numModules = FLASH_KV_DCT_MODULES });
    p.hapPlatform.keyValueStore = &p.keyValueStore;

    HAPPlatformAccessorySetupCreate(
            &p.accessorySetup,
            &(const HAPPlatformAccessorySetupOptions) { .setupInfo = cfg->setupInfo, .setupID = cfg->setupID });
    p.hapPlatform.accessorySetup = &p.accessorySetup;

    HAPPlatformTCPStreamManagerCreate(
            &p.tcpStreamManager,
            &(const HAPPlatformTCPStreamManagerOptions) { .port = HAP_TCP_PORT,
                                                          .maxConcurrentTCPStreams = 9 });
    p.hapPlatform.ip.tcpStreamManager = &p.tcpStreamManager;

    HAPPlatformServiceDiscoveryCreate(&p.serviceDiscovery, &(const HAPPlatformServiceDiscoveryOptions) { 0 });
    p.hapPlatform.ip.serviceDiscovery = &p.serviceDiscovery;

    // No MFi token provisioned: the PAL reports none, which software-authentication needs.
    HAPPlatformMFiTokenAuthCreate(
            &p.mfiTokenAuth, &(const HAPPlatformMFiTokenAuthOptions) { .keyValueStore = &p.keyValueStore });
}

static void init_server(void) {
    static HAPIPSession sessions[HAP_APP_SESSIONS];
    static uint8_t inbound[HAPArrayCount(sessions)][kHAPIPSession_MinimumInboundBufferSize];
    static uint8_t outbound[HAPArrayCount(sessions)][kHAPIPSession_MinimumOutboundBufferSize];
    const hap_app_buffers* b = cfg->buffers;
    for (size_t i = 0; i < HAP_APP_SESSIONS; i++) {
        sessions[i].inboundBuffer.bytes = inbound[i];
        sessions[i].inboundBuffer.numBytes = sizeof inbound[i];
        sessions[i].outboundBuffer.bytes = outbound[i];
        sessions[i].outboundBuffer.numBytes = sizeof outbound[i];
        sessions[i].eventNotifications = &b->events[i * b->numAttributes];
        sessions[i].numEventNotifications = b->numAttributes;
    }
    static uint8_t scratch[kHAPIPSession_MinimumScratchBufferSize];
    static HAPIPAccessoryServerStorage storage;
    storage = (HAPIPAccessoryServerStorage) { .sessions = sessions,
                                                   .numSessions = HAPArrayCount(sessions),
                                                   .readContexts = b->reads,
                                                   .numReadContexts = b->numAttributes,
                                                   .writeContexts = b->writes,
                                                   .numWriteContexts = b->numAttributes,
                                                   .scratchBuffer = { .bytes = scratch,
                                                                      .numBytes = sizeof scratch } };

    p.serverOptions.maxPairings = kHAPPairingStorage_MinElements;
    p.serverOptions.ip.transport = &kHAPAccessoryServerTransport_IP;
    p.serverOptions.ip.accessoryServerStorage = &storage;
    p.serverCallbacks.handleUpdatedState = handle_updated_state;
    p.hapPlatform.authentication.mfiTokenAuth =
            HAPPlatformMFiTokenAuthIsProvisioned(&p.mfiTokenAuth) ? &p.mfiTokenAuth : NULL;

    HAPAccessoryServerCreate(&p.server, &p.serverOptions, &p.hapPlatform, &p.serverCallbacks, NULL);
}

static void hap_task(void* arg HAP_UNUSED) {
    HAPAssert(HAPGetCompatibilityVersion() == HAP_COMPATIBILITY_VERSION);
    HAPPlatformRandomNumberInit(); // seeds the DRBG; the scheduler is running
    init_platform();
    init_server();
    if (cfg->init) {
        cfg->init(&p.server, &p.keyValueStore);
    }
    xSemaphoreGive(ready_sem);

    // The server is started by on_network_up(); the run loop returns only if stopped.
    HAPPlatformRunLoopRun();
    HAPAccessoryServerRelease(&p.server);
    HAPPlatformRunLoopRelease();
    vTaskDelete(NULL);
}

void hap_app_start(const hap_app_config* config) {
    HAPPrecondition(config && config->accessory && config->setupInfo && config->setupID && config->buffers);
    cfg = config;
    ready_sem = xSemaphoreCreateBinary();
    HAPAssert(ready_sem);
    BaseType_t ok = xTaskCreate(hap_task, "hap", HAP_TASK_STACK_WORDS, NULL, HAP_TASK_PRIORITY, NULL);
    HAPAssert(ok == pdPASS);
}

void hap_app_notify_network_up(void) {
    xSemaphoreTake(ready_sem, portMAX_DELAY);
    xSemaphoreGive(ready_sem);
    // The run loop's callback queue can be full for a moment; without this callback the server never starts.
    for (bool logged = false; HAPPlatformRunLoopScheduleCallback(on_network_up, NULL, 0) != kHAPError_None;
         logged = true) {
        if (!logged) {
            HAPLogError(&kHAPLog_Default, "Could not schedule network-up callback, retrying");
        }
        vTaskDelay(pdMS_TO_TICKS(NETWORK_UP_RETRY_MS));
    }
}
