#include "tz.h"
#include "tz_priv.h"

/* Howard Hinnant's days_from_civil / civil_from_days, valid for the proleptic Gregorian calendar. */
int64_t tz_days_from_civil(int32_t y, uint32_t m, uint32_t d)
{
    y -= m <= 2;
    int32_t era = (y >= 0 ? y : y - 399) / 400;
    uint32_t yoe = (uint32_t)(y - era * 400);
    uint32_t doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    uint32_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (int64_t)era * 146097 + (int64_t)doe - 719468;
}

/* 1970-01-01 was a Thursday: ISO weekday 4. */
static uint8_t IsoWeekday(int64_t days)
{
    int64_t w = (days + 3) % 7; /* 0 = Monday */
    if (w < 0) w += 7;
    return (uint8_t)(w + 1);
}

void tz_civil_from_epoch(int64_t t, tz_civil *out)
{
    int64_t days = t / 86400;
    int64_t secs = t % 86400;
    if (secs < 0) {
        secs += 86400;
        days--;
    }
    int64_t z = days + 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    uint32_t doe = (uint32_t)(z - era * 146097);
    uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    uint32_t mp = (5 * doy + 2) / 153;
    uint32_t d = doy - (153 * mp + 2) / 5 + 1;
    uint32_t m = mp < 10 ? mp + 3 : mp - 9;
    out->year = (uint16_t)((int64_t)yoe + era * 400 + (m <= 2));
    out->month = (uint8_t)m;
    out->day = (uint8_t)d;
    out->hour = (uint8_t)(secs / 3600);
    out->minute = (uint8_t)(secs / 60 % 60);
    out->second = (uint8_t)(secs % 60);
    out->weekday = IsoWeekday(days);
}
