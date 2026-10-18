/* TuyaMCU time-reply payloads (cmd 0x1C local, 0x0C GMT). */
#ifndef TM_TIME_H
#define TM_TIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t year; /* full year, e.g. 2026; sent as year % 100 */
    uint8_t month; /* 1-12 */
    uint8_t day;   /* 1-31 */
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t weekday; /* 1 = Monday ... 7 = Sunday (local time only) */
} tm_time;

#define TM_TIME_MAX_LEN 8u

/* Encodes flag, YY MM DD hh mm ss [, weekday]. Local = 8 bytes, GMT = 7 bytes. t == NULL encodes
 * "time not available" (flag 0, all zero). Returns the length; out must hold TM_TIME_MAX_LEN. */
size_t tm_time_encode(uint8_t *out, bool local, const tm_time *t);

#endif
