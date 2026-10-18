/* TuyaMCU data-point records: dpid type len_hi len_lo value. */
#ifndef TM_DP_H
#define TM_DP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { TM_DP_RAW = 0, TM_DP_BOOL = 1, TM_DP_VALUE = 2, TM_DP_STRING = 3, TM_DP_ENUM = 4,
       TM_DP_BITMAP = 5 };

typedef struct {
    uint8_t id;
    uint8_t type;
    uint16_t len;
    const uint8_t *data;
} tm_dp;

/* Is the value length legal for the type? (bool 1, value 4, enum 1, bitmap 1/2/4, raw/string any) */
bool tm_dp_len_ok(uint8_t type, size_t len);

/* Big-endian numeric value of a bool/value/enum/bitmap record (0 for other types). */
uint32_t tm_dp_u32(const tm_dp *dp);
int32_t tm_dp_i32(const tm_dp *dp);

/* Iterates records in [*cur, end). Returns 1 and advances *cur on a record, 0 at the clean end,
 * -1 if the record is truncated (framing lost). Records with an illegal length for their type are
 * still returned; check tm_dp_len_ok. */
int tm_dp_next(const uint8_t **cur, const uint8_t *end, tm_dp *dp);

typedef void (*tm_dp_cb)(void *ctx, const tm_dp *dp);

/* Calls cb for each well-formed record. Returns the number delivered, or -1 if the data ended in a
 * truncated record (those before it are still delivered). Illegal-length records are skipped. */
int tm_dp_decode(const uint8_t *data, size_t len, tm_dp_cb cb, void *ctx);

/* Encoders append one record at out. Return bytes written, or 0 if it does not fit / is illegal. */
size_t tm_dp_put(uint8_t *out, size_t cap, uint8_t id, uint8_t type, const uint8_t *val, size_t len);
size_t tm_dp_put_bool(uint8_t *out, size_t cap, uint8_t id, bool v);
size_t tm_dp_put_value(uint8_t *out, size_t cap, uint8_t id, int32_t v);
size_t tm_dp_put_enum(uint8_t *out, size_t cap, uint8_t id, uint8_t v);
size_t tm_dp_put_bitmap(uint8_t *out, size_t cap, uint8_t id, uint32_t v); /* always 4 bytes */

#endif
