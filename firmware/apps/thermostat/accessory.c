#include "accessory.h"

#include "config.h"
#include "hap_db.h"
#include "thermostat.h"
#include "thermostat_db.h"

#if __has_include("hap_setup_info.h")
#include "hap_setup_info.h"
#else
#error "Missing hap_setup_info.h: generate units/<UNIT>/hap_setup_info.h with firmware/tools/hap_setup.py --category 9 (see hap_setup_info.h.example)"
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
                                  .category = kHAPAccessoryCategory_Thermostats,
                                  .name = THERMOSTAT_NAME,
                                  .manufacturer = THERMOSTAT_MANUFACTURER,
                                  .model = THERMOSTAT_MODEL,
                                  .serialNumber = THERMOSTAT_SERIAL,
                                  .firmwareVersion = THERMOSTAT_FIRMWARE,
                                  .hardwareVersion = "1",
                                  .services = (const HAPService* const[]) { &accessoryInformationService,
                                                                            &hapProtocolInformationService,
                                                                            &pairingService,
                                                                            &thermostatService,
                                                                            &childLockService,
                                                                            NULL },
                                  .callbacks = { .identify = identify } };

static const HAPSetupInfo setupInfo = HAP_SETUP_INFO_INIT;

HAP_APP_BUFFERS(buffers, HAP_DB_SHARED_ATTRIBUTES + THERMOSTAT_DB_ATTRIBUTES);

const HAPAccessory* accessory_get(void) {
    return &accessory;
}

const hap_app_config* accessory_config(void (*onRunning)(void)) {
    static hap_app_config config;
    config = (hap_app_config) { .accessory = &accessory,
                                .setupInfo = &setupInfo,
                                .setupID = HAP_SETUP_ID,
                                .buffers = &buffers,
                                .init = thermostat_init,
                                .onRunning = onRunning };
    return &config;
}
