// Last reported value of every MCU data point, for the web page. Written on the TuyaMCU port task,
// read as a snapshot from any task (short critical sections).
#ifndef DP_CACHE_H
#define DP_CACHE_H

#include <stdint.h>

#include "tm_dp.h"

#define DP_CACHE_MAX     24 // the ET-44W reports ~19
#define DP_CACHE_VAL_MAX 24 // longest kept value; DP119 schedule records are 21 bytes
#define DP_CACHE_DAYS    7  // DP119: one record per weekday, keyed by its single-bit day mask

typedef struct {
    uint8_t id, type, len;
    uint8_t value[DP_CACHE_VAL_MAX];
} dp_cache_entry;

typedef struct {
    unsigned count;
    dp_cache_entry dps[DP_CACHE_MAX];
    dp_cache_entry days[DP_CACHE_DAYS]; // len 0 = not reported yet; [0] = mask 0x01
} dp_cache_snapshot;

void dp_cache_put(const tm_dp* dp);
void dp_cache_get(dp_cache_snapshot* out);

#endif
