// Derived from the HomeKit ADK Lightbulb example (Apache-2.0); see hap_db.h for the license header.
#include "switch.h"

#include "hap_db.h"

#define kIID_Switch                 (HAP_DB_APP_IID_BASE + 0)
#define kIID_SwitchServiceSignature (HAP_DB_APP_IID_BASE + 1)
#define kIID_SwitchName             (HAP_DB_APP_IID_BASE + 2)
#define kIID_SwitchOn               (HAP_DB_APP_IID_BASE + 3)

// KVS: app domains are 0x10-0x3F (ARCHITECTURE.md).
#define kSwitchKVSDomain ((HAPPlatformKeyValueStoreDomain) 0x10)
#define kSwitchKVSKey    ((HAPPlatformKeyValueStoreKey) 0x00)

static struct {
    bool on;
    HAPAccessoryServerRef* server;
    HAPPlatformKeyValueStoreRef kvs;
} sw;

static void load_state(void) {
    bool found;
    size_t numBytes;
    bool on = false;
    HAPError err = HAPPlatformKeyValueStoreGet(sw.kvs, kSwitchKVSDomain, kSwitchKVSKey, &on, sizeof on, &numBytes, &found);
    if (err) {
        HAPLogError(&kHAPLog_Default, "%s: KVS read failed, defaulting to off", __func__);
        return;
    }
    sw.on = found && numBytes == sizeof on && on;
}

static void save_state(void) {
    HAPError err = HAPPlatformKeyValueStoreSet(sw.kvs, kSwitchKVSDomain, kSwitchKVSKey, &sw.on, sizeof sw.on);
    if (err) {
        HAPLogError(&kHAPLog_Default, "%s: KVS write failed", __func__);
    }
}

void switch_init(HAPAccessoryServerRef* server, HAPPlatformKeyValueStoreRef keyValueStore) {
    HAPPrecondition(server);
    HAPPrecondition(keyValueStore);
    sw.server = server;
    sw.kvs = keyValueStore;
    load_state();
}

HAP_RESULT_USE_CHECK
static HAPError handle_on_read(
        HAPAccessoryServerRef* server HAP_UNUSED,
        const HAPBoolCharacteristicReadRequest* request HAP_UNUSED,
        bool* value,
        void* _Nullable context HAP_UNUSED) {
    *value = sw.on;
    return kHAPError_None;
}

HAP_RESULT_USE_CHECK
static HAPError handle_on_write(
        HAPAccessoryServerRef* server,
        const HAPBoolCharacteristicWriteRequest* request,
        bool value,
        void* _Nullable context HAP_UNUSED) {
    HAPLogInfo(&kHAPLog_Default, "Switch: %s", value ? "on" : "off");
    if (sw.on != value) {
        sw.on = value;
        save_state();
        HAPAccessoryServerRaiseEvent(server, request->characteristic, request->service, request->accessory);
    }
    return kHAPError_None;
}

static const HAPDataCharacteristic serviceSignatureCharacteristic = {
    .format = kHAPCharacteristicFormat_Data,
    .iid = kIID_SwitchServiceSignature,
    .characteristicType = &kHAPCharacteristicType_ServiceSignature,
    .debugDescription = kHAPCharacteristicDebugDescription_ServiceSignature,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS_READ_CP,
    .constraints = { .maxLength = 2097152 },
    .callbacks = { .handleRead = HAPHandleServiceSignatureRead, .handleWrite = NULL }
};

static const HAPStringCharacteristic nameCharacteristic = {
    .format = kHAPCharacteristicFormat_String,
    .iid = kIID_SwitchName,
    .characteristicType = &kHAPCharacteristicType_Name,
    .debugDescription = kHAPCharacteristicDebugDescription_Name,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS_READ,
    .constraints = { .maxLength = 64 },
    .callbacks = { .handleRead = HAPHandleNameRead, .handleWrite = NULL }
};

static const HAPBoolCharacteristic onCharacteristic = {
    .format = kHAPCharacteristicFormat_Bool,
    .iid = kIID_SwitchOn,
    .characteristicType = &kHAPCharacteristicType_On,
    .debugDescription = kHAPCharacteristicDebugDescription_On,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS(true, true, true, false),
    .callbacks = { .handleRead = handle_on_read, .handleWrite = handle_on_write }
};

const HAPService switchService = {
    .iid = kIID_Switch,
    .serviceType = &kHAPServiceType_Switch,
    .debugDescription = kHAPServiceDebugDescription_Switch,
    .name = "Switch",
    .properties = { .primaryService = true, .hidden = false, .ble = { .supportsConfiguration = false } },
    .linkedServices = NULL,
    .characteristics = (const HAPCharacteristic* const[]) { &serviceSignatureCharacteristic,
                                                            &nameCharacteristic,
                                                            &onCharacteristic,
                                                            NULL }
};
