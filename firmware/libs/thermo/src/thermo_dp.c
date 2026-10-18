#include "thermo_dp.h"

#include <stddef.h>

#define RO(id, type, name) {id, type, false, 0, 0, 0, name}
#define RW(id, type, min, max, step, name) {id, type, true, min, max, step, name}

/* Ranges from the Tuya thing model (docs/thermostat-firmware.md, data points). */
const thermo_dp_info thermo_dps[] = {
    RW(1, THERMO_W_BOOL, 0, 1, 1, "switch"),
    RW(2, THERMO_W_ENUM, 0, 2, 1, "mode"), /* 0 holiday, 1 schedule, 2 manual */
    RO(3, THERMO_W_ENUM, "heating"),
    RW(16, THERMO_W_VALUE, THERMO_SET_MIN, THERMO_SET_MAX, 5, "setpoint"), /* tenths °C, 0.5 steps */
    RO(24, THERMO_W_VALUE, "current"),
    RO(104, THERMO_DP_RO_BITMAP, "fault"),
    RO(107, THERMO_W_BOOL, "fahrenheit"),
    RW(108, THERMO_W_BOOL, 0, 1, 1, "lock"),
    RW(109, THERMO_W_VALUE, 0, 99, 1, "holiday_days"),
    RW(110, THERMO_W_VALUE, 0, 100, 1, "adaptive"),
    RW(111, THERMO_W_ENUM, 0, 2, 1, "sensor"),
    RW(112, THERMO_W_VALUE, -90, 90, 1, "room_comp"),
    RW(113, THERMO_W_VALUE, -90, 90, 1, "floor_comp"),
    RW(114, THERMO_W_ENUM, 0, 3, 1, "hysteresis"), /* 0.5 / 1 / 2 / 3 °C */
    RO(116, THERMO_W_VALUE, "power_w"),
    RO(117, THERMO_W_VALUE, "heating_time"),
    RO(119, THERMO_DP_RO_RAW, "schedule"),
    RO(121, THERMO_W_VALUE, "floor_limit"),
};
const unsigned thermo_dp_count = sizeof thermo_dps / sizeof thermo_dps[0];

const thermo_dp_info *thermo_dp_find(uint8_t id)
{
    for (unsigned i = 0; i < thermo_dp_count; i++)
        if (thermo_dps[i].id == id) return &thermo_dps[i];
    return NULL;
}

const char *thermo_dp_check_write(uint8_t id, int32_t value)
{
    const thermo_dp_info *d = thermo_dp_find(id);
    if (!d) return "unknown DP";
    if (!d->writable) return "read-only DP";
    if (value < d->min || value > d->max) return "out of range";
    if ((value - d->min) % d->step) return "not a valid step";
    return NULL;
}
