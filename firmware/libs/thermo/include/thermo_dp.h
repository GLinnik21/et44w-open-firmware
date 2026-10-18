/* The ET-44W's data points: type, range and whether the module may write them (for the web page).
 * Pure: no I/O. Host tests: make -C libs/thermo/test.
 *
 * Writes are checked here (type + range) and again by the TuyaMCU core's id allowlist. Read-only on
 * purpose: 115 factory reset (never), 107 °C/°F (would change what 16/24 mean), 116 heater power and
 * 121 floor limit (overheat protection; scale unconfirmed), 119 schedule (write format unverified). */
#ifndef THERMO_DP_H
#define THERMO_DP_H

#include <stdbool.h>
#include <stdint.h>

#include "thermo.h"

typedef struct {
    uint8_t id;
    uint8_t type;     /* thermo_wtype; THERMO_DP_RO_RAW/_BITMAP for read-only non-numeric DPs */
    bool writable;
    int32_t min, max; /* writable only */
    int32_t step;     /* writable only: value - min must be a multiple */
    const char *name; /* JSON key and page label key */
} thermo_dp_info;

enum { THERMO_DP_RO_RAW = 0x10, THERMO_DP_RO_BITMAP = 0x11 };

extern const thermo_dp_info thermo_dps[];
extern const unsigned thermo_dp_count;

const thermo_dp_info *thermo_dp_find(uint8_t id);

/* NULL if the write is allowed, else a short reason. */
const char *thermo_dp_check_write(uint8_t id, int32_t value);

#endif
