/* Minimal POSIX TZ support: "STDoffset[DST[offset][,start[/time],end[/time]]]" with Mm.w.d rules
 * only (what every European/American zone uses), e.g. "JST-9" (Japan) or
 * "CET-1CEST,M3.5.0,M10.5.0/3". Names may be letters or <quoted>. Offsets follow POSIX: positive =
 * west of Greenwich, so "CET-1" is UTC+1. */
#ifndef TZ_H
#define TZ_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t month; /* 1-12 */
    uint8_t week;  /* 1-5, 5 = last */
    uint8_t wday;  /* 0 = Sunday ... 6 = Saturday (POSIX) */
    int32_t time;  /* seconds after local midnight (wall clock before the change), default 7200 */
} tz_rule;

typedef struct {
    int32_t std_offset; /* seconds to add to UTC for standard time */
    int32_t dst_offset; /* seconds to add to UTC during DST */
    bool has_dst;
    tz_rule start, end;
} tz_zone;

typedef struct {
    uint16_t year;
    uint8_t month;   /* 1-12 */
    uint8_t day;     /* 1-31 */
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t weekday; /* 1 = Monday ... 7 = Sunday (ISO; what TuyaMCU expects) */
} tz_civil;

/* Parses a POSIX TZ string. Returns false (and leaves *z as UTC) if it isn't understood. */
bool tz_parse(const char *spec, tz_zone *z);

/* UTC epoch seconds (1970..2105) -> local civil time in zone z. */
void tz_local(const tz_zone *z, int64_t utc, tz_civil *out);

/* UTC epoch seconds -> civil time without any offset. */
void tz_civil_from_epoch(int64_t t, tz_civil *out);

#endif
