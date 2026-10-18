// The HAP task: owns the platform objects, the accessory server and the run loop. Apps supply the
// accessory, setup info, attribute storage and callbacks; everything HomeKit-generic lives here.
#ifndef HAP_APP_H
#define HAP_APP_H

#include "HAP.h"
#include "HAPPlatform+Init.h" // kHAPIPSessionStorage_MinimumNumElements (AmebaZ2 PAL)

/** IP sessions served at once (the ADK minimum). */
#define HAP_APP_SESSIONS kHAPIPSessionStorage_MinimumNumElements

/** Per-attribute server storage, sized by the app's attribute count. Declare with HAP_APP_BUFFERS. */
typedef struct {
    HAPIPEventNotificationRef* events; // [HAP_APP_SESSIONS][numAttributes]
    HAPIPReadContextRef* reads;        // [numAttributes]
    HAPIPWriteContextRef* writes;      // [numAttributes]
    size_t numAttributes;              // services + characteristics in the accessory
} hap_app_buffers;

#define HAP_APP_BUFFERS(name, n) \
    static HAPIPEventNotificationRef name##_events[HAP_APP_SESSIONS][n]; \
    static HAPIPReadContextRef name##_reads[n]; \
    static HAPIPWriteContextRef name##_writes[n]; \
    static const hap_app_buffers name = { &name##_events[0][0], name##_reads, name##_writes, (n) }

typedef struct {
    const HAPAccessory* accessory; // must stay valid while the server runs (static storage)
    const HAPSetupInfo* setupInfo;
    const char* setupID;
    const hap_app_buffers* buffers;
    /** On the HAP task, before the run loop starts (load state, keep server/KVS). May be NULL. */
    void (*init)(HAPAccessoryServerRef* server, HAPPlatformKeyValueStoreRef keyValueStore);
    /** On the HAP task each time the server reaches the running state. May be NULL. */
    void (*onRunning)(void);
} hap_app_config;

/** Creates the HAP task. Call before the scheduler starts; config must stay valid (static). */
void hap_app_start(const hap_app_config* config);

/**
 * Tells the HAP task the network is up so it can start the accessory server. Callable from any
 * task; blocks until the run loop exists (the HAP task creates it first thing) and, if its callback
 * queue is full, until there is room.
 */
void hap_app_notify_network_up(void);

#endif
