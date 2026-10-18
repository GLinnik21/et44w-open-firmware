#include "dp_cache.h"

#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#define SCHEDULE_DP 119

static dp_cache_snapshot cache;

/** Day index of a DP119 record (its first byte has exactly one of bits 0..6 set), or -1. */
static int DayOf(const tm_dp* dp) {
    if (dp->id != SCHEDULE_DP || dp->len < 1) {
        return -1;
    }
    uint8_t mask = dp->data[0];
    for (int i = 0; i < DP_CACHE_DAYS; i++) {
        if (mask == 1u << i) {
            return i;
        }
    }
    return -1;
}

static void Store(dp_cache_entry* e, const tm_dp* dp) {
    e->id = dp->id;
    e->type = dp->type;
    e->len = (uint8_t) (dp->len < DP_CACHE_VAL_MAX ? dp->len : DP_CACHE_VAL_MAX);
    memcpy(e->value, dp->data, e->len);
}

void dp_cache_put(const tm_dp* dp) {
    taskENTER_CRITICAL();
    int day = DayOf(dp);
    if (day >= 0) {
        Store(&cache.days[day], dp);
    } else {
        unsigned i = 0;
        while (i < cache.count && cache.dps[i].id != dp->id) {
            i++;
        }
        if (i < DP_CACHE_MAX) {
            Store(&cache.dps[i], dp);
            if (i == cache.count) {
                cache.count++;
            }
        }
    }
    taskEXIT_CRITICAL();
}

void dp_cache_get(dp_cache_snapshot* out) {
    taskENTER_CRITICAL();
    *out = cache;
    taskEXIT_CRITICAL();
}
