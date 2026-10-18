/* Matter-TLV certificate decoder (Matter spec 6.5). Fields must come in tag order 1..11. */
#include <string.h>
#include "mt_cert.h"
#include "mt_tlv.h"
#include "cert_internal.h"

/* Next element must carry context tag n. */
static mt_err want(mt_tlv_rd *r, uint8_t n)
{
    mt_err e = mt_tlv_next(r);
    if (e) return e == MT_ERR_NOT_FOUND ? MT_ERR_INVALID : e;
    return mt_tlv_is_ctx(r, n) ? MT_OK : MT_ERR_INVALID;
}

static mt_err want_bytes(mt_tlv_rd *r, uint8_t n, size_t min, size_t max, mt_span *out)
{
    MT_TRY(want(r, n));
    return mt_tlv_get_bytes_len(r, min, max, out);
}

static mt_err want_u32(mt_tlv_rd *r, uint8_t n, uint32_t *out)
{
    MT_TRY(want(r, n));
    return mt_tlv_get_u32(r, out);
}

/* Enter the list at the current element, call item() for each member, return the raw member bytes. */
typedef mt_err (*item_fn)(mt_tlv_rd *r, void *ctx);

static mt_err walk_list(mt_tlv_rd *r, mt_tlv_type type, item_fn item, void *ctx, mt_span *raw)
{
    if (r->type != type) return MT_ERR_INVALID;
    size_t start = r->pos;
    MT_TRY(mt_tlv_enter(r));
    mt_err e;
    while (!(e = mt_tlv_next(r)))
        MT_TRY(item(r, ctx));
    if (e != MT_ERR_NOT_FOUND) return e;
    if (raw) *raw = mt_span_of(r->in.p + start, r->pos - start);
    return mt_tlv_exit(r);
}

/* ---- distinguished names ---- */

static mt_err dn_item(mt_tlv_rd *r, void *ctx)
{
    mt_cert_dn *dn = ctx;
    if (r->tag.kind != MT_TAG_CTX) return MT_ERR_INVALID;
    unsigned attr = r->tag.num & 0x7f;
    uint64_t v;
    if (attr >= MT_DN_ATTR_NODE_ID && attr <= MT_DN_ATTR_NOC_CAT) {
        MT_TRY(mt_tlv_get_u64(r, &v));
        if (attr == MT_DN_ATTR_NOC_CAT) {
            if (v > UINT32_MAX || dn->n_cats == MT_CERT_MAX_CATS) return MT_ERR_INVALID;
            dn->cats[dn->n_cats++] = (uint32_t)v;
            return MT_OK;
        }
        uint8_t bit = 0;
        switch (attr) {
        case MT_DN_ATTR_NODE_ID: bit = MT_DN_HAS_NODE; dn->node_id = v; break;
        case MT_DN_ATTR_FABRIC_ID: bit = MT_DN_HAS_FABRIC; dn->fabric_id = v; break;
        case MT_DN_ATTR_RCAC_ID: bit = MT_DN_HAS_RCAC; dn->rcac_id = v; break;
        case MT_DN_ATTR_ICAC_ID: bit = MT_DN_HAS_ICAC; dn->icac_id = v; break;
        default: break; /* firmware-signing id: kept only in the raw list */
        }
        if (dn->has & bit) return MT_ERR_INVALID; /* duplicate */
        dn->has |= bit;
        return MT_OK;
    }
    mt_span s;
    return attr >= 1 && attr <= MT_DN_ATTR_DOMAIN_COMPONENT ? mt_tlv_get_utf8(r, &s) : MT_ERR_UNSUPPORTED;
}

static mt_err dn_parse(mt_tlv_rd *r, mt_cert_dn *dn)
{
    return walk_list(r, MT_TLV_LIST, dn_item, dn, &dn->raw);
}

/* ---- extensions ---- */

typedef struct { mt_cert *c; unsigned last; } ext_ctx;

static mt_err bc_item(mt_tlv_rd *r, void *ctx)
{
    mt_cert *c = ctx;
    if (mt_tlv_is_ctx(r, 1)) return mt_tlv_get_bool(r, &c->is_ca);
    uint8_t v;
    if (!mt_tlv_is_ctx(r, 2) || mt_tlv_get_u8(r, &v) || v > 127) return MT_ERR_INVALID;
    c->path_len = (int8_t)v;
    return MT_OK;
}

static mt_err eku_item(mt_tlv_rd *r, void *ctx)
{
    mt_cert *c = ctx;
    uint8_t v;
    MT_TRY(mt_tlv_get_u8(r, &v));
    if (v < 1 || v > 6 || c->n_eku == MT_CERT_MAX_EKU) return MT_ERR_INVALID;
    c->eku[c->n_eku++] = v;
    return MT_OK;
}

static mt_err ext_item(mt_tlv_rd *r, void *ctx)
{
    ext_ctx *x = ctx;
    mt_cert *c = x->c;
    if (r->tag.kind != MT_TAG_CTX || r->tag.num > 6) return MT_ERR_INVALID;
    unsigned n = (unsigned)r->tag.num;
    if (n < x->last || (n == x->last && n != 6)) return MT_ERR_INVALID; /* ascending, each once */
    x->last = n;
    switch (n) {
    case 1: c->has_bc = true; return walk_list(r, MT_TLV_STRUCT, bc_item, c, NULL);
    case 2: c->has_ku = true; return mt_tlv_get_u16(r, &c->key_usage);
    case 3: return walk_list(r, MT_TLV_ARRAY, eku_item, c, NULL);
    case 4: return mt_tlv_get_bytes_len(r, MT_CERT_KID_LEN, MT_CERT_KID_LEN, &c->skid);
    case 5: return mt_tlv_get_bytes_len(r, MT_CERT_KID_LEN, MT_CERT_KID_LEN, &c->akid);
    default:
        if (c->n_future_ext == MT_CERT_MAX_FUTURE_EXT) return MT_ERR_UNSUPPORTED;
        return mt_tlv_get_bytes_len(r, 1, SIZE_MAX, &c->future_ext[c->n_future_ext++]);
    }
}

/* ---- certificate ---- */

static mt_err want_const(mt_tlv_rd *r, uint8_t n, uint32_t expect)
{
    uint32_t v;
    MT_TRY(want_u32(r, n, &v));
    return v == expect ? MT_OK : MT_ERR_UNSUPPORTED;
}

static mt_err decode_fields(mt_tlv_rd *r, mt_cert *c)
{
    MT_TRY(want_bytes(r, 1, 1, MT_CERT_SERIAL_MAX, &c->serial));
    MT_TRY(want_const(r, 2, 1)); /* ecdsa-with-SHA256 */
    MT_TRY(want(r, 3)); MT_TRY(dn_parse(r, &c->issuer));
    MT_TRY(want_u32(r, 4, &c->not_before));
    MT_TRY(want_u32(r, 5, &c->not_after));
    MT_TRY(want(r, 6)); MT_TRY(dn_parse(r, &c->subject));
    MT_TRY(want_const(r, 7, 1)); /* id-ecPublicKey */
    MT_TRY(want_const(r, 8, 1)); /* prime256v1 */
    MT_TRY(want_bytes(r, 9, MT_CERT_PUBKEY_LEN, MT_CERT_PUBKEY_LEN, &c->pubkey));
    if (c->pubkey.p[0] != 0x04) return MT_ERR_INVALID;
    MT_TRY(want(r, 10));
    ext_ctx x = { c, 0 };
    MT_TRY(walk_list(r, MT_TLV_LIST, ext_item, &x, NULL));
    return want_bytes(r, 11, MT_P256_SIG_LEN, MT_P256_SIG_LEN, &c->sig);
}

mt_err mt_cert_decode(mt_span tlv, mt_cert *c)
{
    memset(c, 0, sizeof *c);
    c->path_len = -1;
    c->tlv = tlv;
    if (tlv.len > MT_CERT_SCRATCH) return MT_ERR_INVALID;
    mt_tlv_rd r;
    MT_TRY(mt_tlv_open_struct(&r, tlv));
    MT_TRY(decode_fields(&r, c));
    if (mt_tlv_next(&r) != MT_ERR_NOT_FOUND) return MT_ERR_INVALID; /* nothing after tag 11 */
    MT_TRY(mt_tlv_exit(&r));
    return mt_tlv_next(&r) == MT_ERR_NOT_FOUND ? MT_OK : MT_ERR_INVALID; /* nothing after the struct */
}
