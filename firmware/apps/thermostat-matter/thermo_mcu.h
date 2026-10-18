// TuyaMCU glue: which reports feed the thermo model, thermo writes as TuyaMCU DP writes, and the MCU's time
// requests. No Matter code.
#ifndef THERMO_MCU_H
#define THERMO_MCU_H

#include <stdbool.h>
#include <stdint.h>

#include "thermo.h"
#include "tuyamcu.h"

// A numeric DP report the thermo model uses: *value set, true. Anything else (raw, string, other DPs): false.
bool thermo_mcu_report(const tm_dp* dp, int32_t* value);

// Any task: queues one DP write (type is a thermo_wtype). False if the queue is full. The TuyaMCU core's
// allowlist still applies.
bool thermo_mcu_write(uint8_t dp, thermo_wtype type, int32_t value);

// tuyamcu_port_config.get_time: SNTP local (or UTC) time from clock.c.
bool thermo_mcu_time(bool local, tm_time* t, void* ctx);

#endif
