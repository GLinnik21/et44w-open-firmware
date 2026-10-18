// The thermostat state on the HAP task: a thermo model fed by MCU reports, written from HomeKit,
// debounced into DP writes, and mirrored to the MCU's Wi-Fi icon. All functions except
// thermostat_post_report run on the HAP task.
#ifndef THERMOSTAT_H
#define THERMOSTAT_H

#include "HAP.h"

#include "thermo.h"

/** hap_app init callback: keeps the server, starts the timers. */
void thermostat_init(HAPAccessoryServerRef* server, HAPPlatformKeyValueStoreRef keyValueStore);

/** Any task: queues one DP report (thermo_mcu_report passed it) to the HAP task. */
void thermostat_post_report(uint8_t dp, int32_t value);

/** Read-only model for the HAP read handlers. */
const thermo* thermostat_model(void);

/** HomeKit writes (from the HAP write handlers). False = value not supported. */
bool thermostat_set_target_state(uint8_t hk);
bool thermostat_set_target_c(float celsius);
bool thermostat_set_locked(bool on);

#endif
