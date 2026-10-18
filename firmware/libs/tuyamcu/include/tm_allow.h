/* DP write allowlist. The module may only command these data points on the thermostat MCU; anything
 * else (notably DP 115 factory reset) is refused. Fixed at compile time on purpose. */
#ifndef TM_ALLOW_H
#define TM_ALLOW_H

#include <stdbool.h>
#include <stdint.h>

bool tm_dp_write_allowed(uint8_t dpid);

#endif
