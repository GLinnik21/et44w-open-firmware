#ifndef TZ_PRIV_H
#define TZ_PRIV_H

#include <stdint.h>

/* Days since 1970-01-01 of a proleptic Gregorian date. */
int64_t tz_days_from_civil(int32_t y, uint32_t m, uint32_t d);

#endif
