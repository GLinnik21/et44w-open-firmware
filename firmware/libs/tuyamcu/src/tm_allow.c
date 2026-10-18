#include "tm_allow.h"

/* ET-44W (see docs/thermostat-firmware.md, data points; ranges are checked by libs/thermo thermo_dp.c, whose host test
 * keeps the two lists equal): 1 switch, 2 mode, 16 temp_set, 108 Lock, 109 holiday days,
 * 110 adaptive, 111 sensor select, 112/113 room/floor calibration, 114 hysteresis.
 * Never: 115 factory reset. Not 107 (°C/°F): switching units would change what DP16/24 mean.
 * Not 116 heater power / 121 floor limit (overheat protection) / 119 schedule (format unverified). */
static const uint8_t allowed[] = {1, 2, 16, 108, 109, 110, 111, 112, 113, 114};

bool tm_dp_write_allowed(uint8_t dpid)
{
    for (unsigned i = 0; i < sizeof allowed; i++)
        if (allowed[i] == dpid) return true;
    return false;
}
