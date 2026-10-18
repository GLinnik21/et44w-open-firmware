#include "tm_dp.h"

#define DP_HDR 4u

bool tm_dp_len_ok(uint8_t type, size_t len)
{
    switch (type) {
    case TM_DP_BOOL:
    case TM_DP_ENUM:
        return len == 1;
    case TM_DP_VALUE:
        return len == 4;
    case TM_DP_BITMAP:
        return len == 1 || len == 2 || len == 4;
    case TM_DP_RAW:
    case TM_DP_STRING:
        return len <= 0xFFFFu;
    default:
        return false;
    }
}

uint32_t tm_dp_u32(const tm_dp *dp)
{
    if (dp->type != TM_DP_BOOL && dp->type != TM_DP_VALUE && dp->type != TM_DP_ENUM &&
        dp->type != TM_DP_BITMAP)
        return 0;
    uint32_t v = 0;
    for (uint16_t i = 0; i < dp->len && i < 4; i++) v = (v << 8) | dp->data[i];
    return v;
}

int32_t tm_dp_i32(const tm_dp *dp)
{
    return (int32_t)tm_dp_u32(dp);
}

int tm_dp_next(const uint8_t **cur, const uint8_t *end, tm_dp *dp)
{
    const uint8_t *p = *cur;
    if (p >= end) return 0;
    if ((size_t)(end - p) < DP_HDR) return -1;
    uint16_t len = (uint16_t)((p[2] << 8) | p[3]);
    if ((size_t)(end - p) - DP_HDR < len) return -1;
    dp->id = p[0];
    dp->type = p[1];
    dp->len = len;
    dp->data = p + DP_HDR;
    *cur = p + DP_HDR + len;
    return 1;
}

int tm_dp_decode(const uint8_t *data, size_t len, tm_dp_cb cb, void *ctx)
{
    const uint8_t *cur = data, *end = data + len;
    tm_dp dp;
    int n = 0, r;
    while ((r = tm_dp_next(&cur, end, &dp)) > 0) {
        if (!tm_dp_len_ok(dp.type, dp.len)) continue;
        cb(ctx, &dp);
        n++;
    }
    return r < 0 ? -1 : n;
}

size_t tm_dp_put(uint8_t *out, size_t cap, uint8_t id, uint8_t type, const uint8_t *val, size_t len)
{
    if (!tm_dp_len_ok(type, len) || cap < DP_HDR + len) return 0;
    out[0] = id;
    out[1] = type;
    out[2] = (uint8_t)(len >> 8);
    out[3] = (uint8_t)len;
    for (size_t i = 0; i < len; i++) out[DP_HDR + i] = val[i];
    return DP_HDR + len;
}

static size_t put_be(uint8_t *out, size_t cap, uint8_t id, uint8_t type, uint32_t v, size_t n)
{
    uint8_t b[4];
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
    return tm_dp_put(out, cap, id, type, b, n);
}

size_t tm_dp_put_bool(uint8_t *out, size_t cap, uint8_t id, bool v)
{
    return put_be(out, cap, id, TM_DP_BOOL, v ? 1u : 0u, 1);
}

size_t tm_dp_put_value(uint8_t *out, size_t cap, uint8_t id, int32_t v)
{
    return put_be(out, cap, id, TM_DP_VALUE, (uint32_t)v, 4);
}

size_t tm_dp_put_enum(uint8_t *out, size_t cap, uint8_t id, uint8_t v)
{
    return put_be(out, cap, id, TM_DP_ENUM, v, 1);
}

size_t tm_dp_put_bitmap(uint8_t *out, size_t cap, uint8_t id, uint32_t v)
{
    return put_be(out, cap, id, TM_DP_BITMAP, v, 4);
}
