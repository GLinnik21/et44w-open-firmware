#include "tm_time.h"

size_t tm_time_encode(uint8_t *out, bool local, const tm_time *t)
{
    size_t n = local ? 8 : 7;
    for (size_t i = 0; i < n; i++) out[i] = 0;
    if (!t) return n;
    out[0] = 1;
    out[1] = (uint8_t)(t->year % 100);
    out[2] = t->month;
    out[3] = t->day;
    out[4] = t->hour;
    out[5] = t->minute;
    out[6] = t->second;
    if (local) out[7] = t->weekday;
    return n;
}
