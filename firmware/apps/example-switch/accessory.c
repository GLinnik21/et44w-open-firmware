#include "accessory.h"

#include "hap_db.h"
#include "switch.h"

#if __has_include("hap_setup_info.h")
#include "hap_setup_info.h"
#else
#error "Missing apps/example-switch/hap_setup_info.h: generate it with tools/hap_setup.py (see hap_setup_info.h.example)"
#endif

static HAPError identify(
        HAPAccessoryServerRef* server HAP_UNUSED,
        const HAPAccessoryIdentifyRequest* request HAP_UNUSED,
        void* _Nullable context HAP_UNUSED) {
    HAPLogInfo(&kHAPLog_Default, "Identify");
    return kHAPError_None;
}

// Not const: the ADK may change the name (BCT manual name change).
static HAPAccessory accessory = { .aid = 1,
                                  .category = kHAPAccessoryCategory_Switches,
                                  .name = "Example Switch",
                                  .manufacturer = "Example",
                                  .model = "Switch1,1",
                                  .serialNumber = "000000000001",
                                  .firmwareVersion = "1",
                                  .hardwareVersion = "1",
                                  .services = (const HAPService* const[]) { &accessoryInformationService,
                                                                            &hapProtocolInformationService,
                                                                            &pairingService,
                                                                            &switchService,
                                                                            NULL },
                                  .callbacks = { .identify = identify } };

static const HAPSetupInfo setupInfo = HAP_SETUP_INFO_INIT;

HAP_APP_BUFFERS(buffers, HAP_DB_SHARED_ATTRIBUTES + SWITCH_ATTRIBUTES);

const hap_app_config* accessory_config(void (*onRunning)(void)) {
    static hap_app_config config;
    config = (hap_app_config) { .accessory = &accessory,
                                .setupInfo = &setupInfo,
                                .setupID = HAP_SETUP_ID,
                                .buffers = &buffers,
                                .init = switch_init,
                                .onRunning = onRunning };
    return &config;
}
