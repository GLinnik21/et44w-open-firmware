#include <string.h>
#include "mt_tlv.h"
#include "mt_tlv_priv.h"

bool mt_tlv_tag_eq(mt_tlv_tag a, mt_tlv_tag b)
{
    if (a.kind != b.kind) return false;
    switch (a.kind) {
    case MT_TAG_ANON: return true;
    case MT_TAG_FQ: return a.vendor == b.vendor && a.profile == b.profile && a.num == b.num;
    default: return a.num == b.num;
    }
}

void mt_tlv_rd_init(mt_tlv_rd *r, mt_span in)
{
    memset(r, 0, sizeof *r);
    r->in = in;
}

static uint64_t le(const uint8_t *p, size_t n)
{
    uint64_t v = 0;
    while (n--) v = v << 8 | p[n];
    return v;
}

static bool take(mt_tlv_rd *r, size_t n, const uint8_t **p)
{
    if (n > r->in.len - r->pos) return false;
    *p = r->in.p + r->pos;
    r->pos += n;
    return true;
}

static mt_err read_tag(mt_tlv_rd *r, unsigned form)
{
    static const uint8_t kind[8] = { MT_TAG_ANON, MT_TAG_CTX, MT_TAG_COMMON, MT_TAG_COMMON,
                                     MT_TAG_IMPLICIT, MT_TAG_IMPLICIT, MT_TAG_FQ, MT_TAG_FQ };
    static const uint8_t numlen[8] = { 0, 1, 2, 4, 2, 4, 2, 4 };
    const uint8_t *p;
    mt_tlv_tag t = { (mt_tlv_tagkind)kind[form], 0, 0, 0 };
    if (t.kind == MT_TAG_FQ) {
        if (!take(r, 4, &p)) return MT_ERR_INVALID;
        t.vendor = mt_get_le16(p);
        t.profile = mt_get_le16(p + 2);
    }
    if (!take(r, numlen[form], &p)) return MT_ERR_INVALID;
    t.num = (uint32_t)le(p, numlen[form]);
    r->tag = t;
    return MT_OK;
}

static mt_err read_value(mt_tlv_rd *r, unsigned et)
{
    const uint8_t *p;
    size_t n = (size_t)1 << (et & 3);
    if (et <= T_UINT + 3) {
        if (!take(r, n, &p)) return MT_ERR_INVALID;
        r->val = le(p, n);
        if (et < T_UINT && n < 8 && (r->val >> (8 * n - 1) & 1)) r->val |= ~(uint64_t)0 << (8 * n);
        r->type = et < T_UINT ? MT_TLV_SINT : MT_TLV_UINT;
    } else if (et <= T_TRUE) {
        r->val = et == T_TRUE;
        r->type = MT_TLV_BOOL;
    } else if (et <= T_F64) {
        n = et == T_F32 ? 4 : 8;
        if (!take(r, n, &p)) return MT_ERR_INVALID;
        r->val = le(p, n);
        r->type = et == T_F32 ? MT_TLV_F32 : MT_TLV_F64;
    } else if (et < T_BYTES + 4) {
        if (!take(r, n, &p)) return MT_ERR_INVALID;
        uint64_t len = le(p, n);
        if (len > r->in.len - r->pos) return MT_ERR_INVALID;
        r->str = mt_span_of(r->in.p + r->pos, (size_t)len);
        r->pos += (size_t)len;
        r->type = et < T_BYTES ? MT_TLV_UTF8 : MT_TLV_BYTES;
    } else if (et == T_NULL) {
        r->type = MT_TLV_NULL;
    } else if (et >= T_STRUCT && et <= T_LIST) {
        r->type = (mt_tlv_type)(MT_TLV_STRUCT + (et - T_STRUCT));
    } else {
        return MT_ERR_INVALID;
    }
    return MT_OK;
}

/* Parse one element at pos. MT_ERR_NOT_FOUND = it was an end-of-container (consumed). */
static mt_err parse(mt_tlv_rd *r)
{
    r->type = MT_TLV_NONE;
    if (r->pos >= r->in.len) return MT_ERR_INVALID;
    unsigned ctrl = r->in.p[r->pos++], et = ctrl & 0x1f, form = ctrl >> 5;
    if (et == T_END) return form ? MT_ERR_INVALID : MT_ERR_NOT_FOUND;
    mt_err e = read_tag(r, form);
    return e ? e : read_value(r, et);
}

/* Consume elements until `nest` more end-of-container markers have been seen. */
static mt_err skip(mt_tlv_rd *r, size_t nest)
{
    while (nest) {
        mt_err e = parse(r);
        if (e == MT_ERR_NOT_FOUND) nest--;
        else if (e) return e;
        else if (mt_tlv_is_container(r)) nest++;
    }
    r->type = MT_TLV_NONE;
    return MT_OK;
}

mt_err mt_tlv_next(mt_tlv_rd *r)
{
    if (mt_tlv_is_container(r)) {
        mt_err e = skip(r, 1);
        if (e) return e;
    }
    if (r->depth == 0 && r->pos == r->in.len) {
        r->type = MT_TLV_NONE;
        return MT_ERR_NOT_FOUND;
    }
    size_t at = r->pos;
    mt_err e = parse(r);
    if (e == MT_ERR_NOT_FOUND) {
        if (r->depth == 0) return MT_ERR_INVALID;
        r->pos = at; /* leave the marker for mt_tlv_exit */
    }
    return e;
}

mt_err mt_tlv_enter(mt_tlv_rd *r)
{
    if (!mt_tlv_is_container(r)) return MT_ERR_STATE;
    r->depth++;
    r->type = MT_TLV_NONE;
    return MT_OK;
}

mt_err mt_tlv_exit(mt_tlv_rd *r)
{
    if (r->depth == 0) return MT_ERR_STATE;
    mt_err e = skip(r, 1 + mt_tlv_is_container(r));
    if (!e) r->depth--;
    return e;
}

mt_err mt_tlv_find_ctx(mt_tlv_rd *r, uint8_t n)
{
    mt_err e;
    while (!(e = mt_tlv_next(r)))
        if (mt_tlv_is_ctx(r, n)) return MT_OK;
    return e;
}

static mt_err not_int(const mt_tlv_rd *r)
{
    return r->type == MT_TLV_SINT || r->type == MT_TLV_UINT ? MT_OK : MT_ERR_INVALID;
}

mt_err mt_tlv_get_u64(const mt_tlv_rd *r, uint64_t *out)
{
    if (not_int(r) || (r->type == MT_TLV_SINT && (int64_t)r->val < 0)) return MT_ERR_INVALID;
    *out = r->val;
    return MT_OK;
}

mt_err mt_tlv_get_i64(const mt_tlv_rd *r, int64_t *out)
{
    if (not_int(r) || (r->type == MT_TLV_UINT && r->val > INT64_MAX)) return MT_ERR_INVALID;
    *out = (int64_t)r->val;
    return MT_OK;
}

static mt_err get_u(const mt_tlv_rd *r, uint64_t max, uint64_t *out)
{
    mt_err e = mt_tlv_get_u64(r, out);
    return e ? e : (*out > max ? MT_ERR_INVALID : MT_OK);
}

static mt_err get_i(const mt_tlv_rd *r, int64_t min, int64_t max, int64_t *out)
{
    mt_err e = mt_tlv_get_i64(r, out);
    return e ? e : (*out < min || *out > max ? MT_ERR_INVALID : MT_OK);
}

#define GET_U(name, T, max) mt_err mt_tlv_get_##name(const mt_tlv_rd *r, T *out) { \
    uint64_t v; mt_err e = get_u(r, max, &v); if (!e) *out = (T)v; return e; }
#define GET_I(name, T, min, max) mt_err mt_tlv_get_##name(const mt_tlv_rd *r, T *out) { \
    int64_t v; mt_err e = get_i(r, min, max, &v); if (!e) *out = (T)v; return e; }
GET_U(u32, uint32_t, UINT32_MAX)
GET_U(u16, uint16_t, UINT16_MAX)
GET_U(u8, uint8_t, UINT8_MAX)
GET_I(i32, int32_t, INT32_MIN, INT32_MAX)
GET_I(i16, int16_t, INT16_MIN, INT16_MAX)
GET_I(i8, int8_t, INT8_MIN, INT8_MAX)

mt_err mt_tlv_get_bool(const mt_tlv_rd *r, bool *out)
{
    if (r->type != MT_TLV_BOOL) return MT_ERR_INVALID;
    *out = r->val != 0;
    return MT_OK;
}

mt_err mt_tlv_get_f32(const mt_tlv_rd *r, float *out)
{
    uint32_t bits = (uint32_t)r->val;
    if (r->type != MT_TLV_F32) return MT_ERR_INVALID;
    memcpy(out, &bits, sizeof bits);
    return MT_OK;
}

mt_err mt_tlv_get_f64(const mt_tlv_rd *r, double *out)
{
    float f;
    if (r->type == MT_TLV_F32) {
        mt_tlv_get_f32(r, &f);
        *out = f;
        return MT_OK;
    }
    if (r->type != MT_TLV_F64) return MT_ERR_INVALID;
    memcpy(out, &r->val, sizeof *out);
    return MT_OK;
}

mt_err mt_tlv_get_utf8(const mt_tlv_rd *r, mt_span *out)
{
    if (r->type != MT_TLV_UTF8) return MT_ERR_INVALID;
    *out = r->str;
    return MT_OK;
}

mt_err mt_tlv_get_bytes(const mt_tlv_rd *r, mt_span *out)
{
    if (r->type != MT_TLV_BYTES) return MT_ERR_INVALID;
    *out = r->str;
    return MT_OK;
}

mt_err mt_tlv_get_bytes_len(const mt_tlv_rd *r, size_t min, size_t max, mt_span *out)
{
    MT_TRY(mt_tlv_get_bytes(r, out));
    return out->len < min || out->len > max ? MT_ERR_INVALID : MT_OK;
}

mt_err mt_tlv_open_struct(mt_tlv_rd *r, mt_span in)
{
    mt_tlv_rd_init(r, in);
    mt_err e = mt_tlv_next(r);
    if (e) return e == MT_ERR_NOT_FOUND ? MT_ERR_INVALID : e;
    if (r->type != MT_TLV_STRUCT || r->tag.kind != MT_TAG_ANON) return MT_ERR_INVALID;
    return mt_tlv_enter(r);
}
