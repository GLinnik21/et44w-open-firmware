#include <string.h>
#include "mt_tlv.h"
#include "mt_tlv_priv.h"

void mt_tlv_wr_init(mt_tlv_wr *w, mt_buf buf)
{
    memset(w, 0, sizeof *w);
    w->buf = buf;
}

mt_err mt_tlv_wr_done(const mt_tlv_wr *w, mt_span *out)
{
    if (w->depth) return MT_ERR_STATE;
    *out = mt_tlv_wr_span(w);
    return MT_OK;
}

mt_tlv_mark mt_tlv_wr_mark(const mt_tlv_wr *w)
{
    mt_tlv_mark m = { w->len, w->depth };
    return m;
}

void mt_tlv_wr_rollback(mt_tlv_wr *w, mt_tlv_mark m)
{
    w->len = m.len;
    w->depth = m.depth;
}

static void put_le(uint8_t *p, uint64_t v, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* Tag form (bits 7..5 of the control byte); *nn = bytes of the tag number. */
static unsigned tag_form(mt_tlv_tag t, size_t *nn)
{
    bool wide = t.num > 0xFFFF;
    switch (t.kind) {
    case MT_TAG_CTX: *nn = 1; return 1;
    case MT_TAG_COMMON: *nn = wide ? 4 : 2; return wide ? 3 : 2;
    case MT_TAG_IMPLICIT: *nn = wide ? 4 : 2; return wide ? 5 : 4;
    case MT_TAG_FQ: *nn = wide ? 4 : 2; return wide ? 7 : 6;
    default: *nn = 0; return 0;
    }
}

/* One element: control byte, tag, `vn` value bytes from v, then `bn` body bytes. */
static mt_err put(mt_tlv_wr *w, mt_tlv_tag t, unsigned etype, uint64_t v, size_t vn,
                  const uint8_t *body, size_t bn)
{
    size_t nn, room = w->buf.cap - w->len;
    unsigned form = tag_form(t, &nn);
    size_t tn = nn + (t.kind == MT_TAG_FQ ? 4 : 0);
    if (t.kind == MT_TAG_CTX && t.num > 0xFF) return MT_ERR_INVALID;
    if (room < w->reserve || room - w->reserve < 1 + tn + vn || room - w->reserve - 1 - tn - vn < bn)
        return MT_ERR_BUFFER_TOO_SMALL;
    uint8_t *p = w->buf.p + w->len;
    *p++ = (uint8_t)(form << 5 | etype);
    if (t.kind == MT_TAG_FQ) {
        mt_put_le16(p, t.vendor);
        mt_put_le16(p + 2, t.profile);
        p += 4;
    }
    put_le(p, t.num, nn);
    put_le(p + nn, v, vn);
    if (bn) memcpy(p + nn + vn, body, bn);
    w->len += 1 + tn + vn + bn;
    return MT_OK;
}

/* Smallest width code 0..3 (1, 2, 4, 8 bytes) that holds the value. */
static unsigned width_code(uint64_t v)
{
    return v <= 0xFF ? 0 : v <= 0xFFFF ? 1 : v <= 0xFFFFFFFFu ? 2 : 3;
}

mt_err mt_tlv_put_u(mt_tlv_wr *w, mt_tlv_tag tag, uint64_t v)
{
    unsigned c = width_code(v);
    return put(w, tag, T_UINT + c, v, (size_t)1 << c, NULL, 0);
}

mt_err mt_tlv_put_i(mt_tlv_wr *w, mt_tlv_tag tag, int64_t v)
{
    unsigned c = v >= INT8_MIN && v <= INT8_MAX ? 0 : v >= INT16_MIN && v <= INT16_MAX ? 1
               : v >= INT32_MIN && v <= INT32_MAX ? 2 : 3;
    return put(w, tag, T_SINT + c, (uint64_t)v, (size_t)1 << c, NULL, 0);
}

mt_err mt_tlv_put_bool(mt_tlv_wr *w, mt_tlv_tag tag, bool v)
{
    return put(w, tag, T_FALSE + (v ? 1 : 0), 0, 0, NULL, 0);
}

mt_err mt_tlv_put_null(mt_tlv_wr *w, mt_tlv_tag tag)
{
    return put(w, tag, T_NULL, 0, 0, NULL, 0);
}

mt_err mt_tlv_put_f32(mt_tlv_wr *w, mt_tlv_tag tag, float v)
{
    uint32_t bits;
    memcpy(&bits, &v, sizeof bits);
    return put(w, tag, T_F32, bits, 4, NULL, 0);
}

mt_err mt_tlv_put_f64(mt_tlv_wr *w, mt_tlv_tag tag, double v)
{
    uint64_t bits;
    memcpy(&bits, &v, sizeof bits);
    return put(w, tag, T_F64, bits, 8, NULL, 0);
}

static mt_err put_str(mt_tlv_wr *w, mt_tlv_tag tag, unsigned base, const uint8_t *s, size_t len)
{
    unsigned c = width_code(len);
    if (c == 3) return MT_ERR_INVALID; /* length field is at most 4 bytes here */
    return put(w, tag, base + c, len, (size_t)1 << c, s, len);
}

mt_err mt_tlv_put_utf8(mt_tlv_wr *w, mt_tlv_tag tag, const char *s, size_t len)
{
    return put_str(w, tag, T_UTF8, (const uint8_t *)s, len);
}

mt_err mt_tlv_put_bytes(mt_tlv_wr *w, mt_tlv_tag tag, mt_span b)
{
    return put_str(w, tag, T_BYTES, b.p, b.len);
}

mt_err mt_tlv_put_raw(mt_tlv_wr *w, mt_span enc)
{
    size_t room = w->buf.cap - w->len;
    if (room < w->reserve || room - w->reserve < enc.len) return MT_ERR_BUFFER_TOO_SMALL;
    memcpy(w->buf.p + w->len, enc.p, enc.len);
    w->len += enc.len;
    return MT_OK;
}

mt_err mt_tlv_start(mt_tlv_wr *w, mt_tlv_tag tag, mt_tlv_type type)
{
    if (type < MT_TLV_STRUCT || type > MT_TLV_LIST) return MT_ERR_INVALID;
    mt_err e = put(w, tag, T_STRUCT + (unsigned)(type - MT_TLV_STRUCT), 0, 0, NULL, 0);
    if (!e) w->depth++;
    return e;
}

mt_err mt_tlv_end(mt_tlv_wr *w)
{
    if (!w->depth) return MT_ERR_STATE;
    if (w->len >= w->buf.cap) return MT_ERR_BUFFER_TOO_SMALL;
    w->buf.p[w->len++] = T_END;
    w->depth--;
    return MT_OK;
}
