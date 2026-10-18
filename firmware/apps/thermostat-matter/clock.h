// Wall-clock time from SNTP, converted to local time with TM_TZ (matter_config.h). Thread-safe reads.
#ifndef CLOCK_H
#define CLOCK_H

#include <stdbool.h>
#include <stdint.h>

#include "tuyamcu.h"

/** Starts SNTP once (later calls do nothing). Call when the network is up. */
void clock_start(void);

/** Fills *t with local (or UTC) time. False until SNTP has synced. */
bool clock_get(bool local, tm_time* t);

/** Seconds since 1970 (UTC), 0 until SNTP has synced. */
int64_t clock_unix(void);

#endif
