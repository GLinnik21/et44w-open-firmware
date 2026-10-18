/* CASE message codecs (spec 4.14.2: sigma-1-struct, sigma-2-struct, sigma-2-tbsdata, sigma-2-tbedata,
 * sigma-3-struct, sigma-3-tbsdata, sigma-3-tbedata). Parsers accept fields in any order, ignore unknown
 * tags (future-proofing, as connectedhomeip's ParseSigma1/ParseSigma3 do), reject duplicates and require
 * the outer structure to be properly closed. */
#include <string.h>

#include "case_internal.h"
#include "mt_tlv.h"

/* ---- parsing ---- */

/* Next context-tagged field of the open structure: *tag = its number, 0 for a field to skip.
 * MT_ERR_NOT_FOUND at the (properly closed) end of the structure. */
static mt_err next_field(mt_tlv_rd *r, unsigned *seen, unsigned *tag)
{
    mt_err e = mt_tlv_next(r);
    if (e) return e;
    *tag = 0;
    if (r->tag.kind != MT_TAG_CTX || r->tag.num == 0 || r->tag.num > 15) return MT_OK;
    unsigned bit = 1u << r->tag.num;
    if (*seen & bit) return MT_ERR_INVALID; /* duplicate */
    *seen |= bit;
    *tag = r->tag.num;
    return MT_OK;
}

static mt_err get_fixed(const mt_tlv_rd *r, size_t n, const uint8_t **out)
{
    mt_span b;
    MT_TRY(mt_tlv_get_bytes_len(r, n, n, &b));
    *out = b.p;
    return MT_OK;
}

/* session-parameter-struct: only the MRP fields matter to us, everything else is skipped. */
static mt_err parse_peer(mt_tlv_rd *r, mt_sc_peer_params *o)
{
    return r->type == MT_TLV_STRUCT ? mt_sc_peer_parse(r, o) : MT_ERR_INVALID;
}

#define BIT(n) (1u << (n))

mt_err case_parse_sigma1(mt_span in, case_sigma1 *s)
{
    mt_tlv_rd r;
    unsigned seen = 0, tag;
    const uint8_t *rid = NULL, *mic = NULL;
    mt_err e;
    memset(s, 0, sizeof *s);
    MT_TRY(mt_tlv_open_struct(&r, in));
    while (!(e = next_field(&r, &seen, &tag))) {
        switch (tag) {
        case 1: e = get_fixed(&r, CASE_RANDOM_LEN, &s->random); break;
        case 2: e = mt_tlv_get_u16(&r, &s->session_id); break;
        case 3: e = get_fixed(&r, MT_DEST_ID_LEN, &s->dest_id); break;
        case 4: e = get_fixed(&r, MT_P256_POINT_LEN, &s->eph_pub); break;
        case 5: e = parse_peer(&r, &s->peer); break;
        case 6: e = get_fixed(&r, MT_CASE_RESUMPTION_ID_LEN, &rid); break;
        case 7: e = get_fixed(&r, MT_CCM_TAG_LEN, &mic); break;
        default: break;
        }
        if (e) return e;
    }
    if (e != MT_ERR_NOT_FOUND) return e;
    unsigned req = BIT(1) | BIT(2) | BIT(3) | BIT(4);
    if ((seen & req) != req) return MT_ERR_INVALID;
    if (!rid != !mic) return MT_ERR_INVALID; /* resumptionID and initiatorResumeMIC come together */
    s->resumption = rid != NULL;
    return MT_OK;
}

mt_err case_parse_sigma3(mt_span in, mt_span *encrypted)
{
    mt_tlv_rd r;
    unsigned seen = 0, tag;
    mt_err e;
    MT_TRY(mt_tlv_open_struct(&r, in));
    while (!(e = next_field(&r, &seen, &tag)))
        if (tag == 1 && (e = mt_tlv_get_bytes(&r, encrypted))) return e;
    if (e != MT_ERR_NOT_FOUND) return e;
    if (!(seen & BIT(1)) || encrypted->len <= MT_CCM_TAG_LEN) return MT_ERR_INVALID;
    return MT_OK;
}

mt_err case_parse_tbe3(mt_span in, case_tbe3 *t)
{
    mt_tlv_rd r;
    unsigned seen = 0, tag;
    mt_err e;
    memset(t, 0, sizeof *t);
    MT_TRY(mt_tlv_open_struct(&r, in));
    while (!(e = next_field(&r, &seen, &tag))) {
        switch (tag) {
        case 1: e = mt_tlv_get_bytes_len(&r, 1, MT_CASE_CERT_MAX, &t->noc); break;
        case 2: e = mt_tlv_get_bytes_len(&r, 1, MT_CASE_CERT_MAX, &t->icac); break;
        case 3: e = get_fixed(&r, MT_P256_SIG_LEN, &t->sig); break;
        default: break;
        }
        if (e) return e;
    }
    if (e != MT_ERR_NOT_FOUND) return e;
    return (seen & (BIT(1) | BIT(3))) == (BIT(1) | BIT(3)) ? MT_OK : MT_ERR_INVALID;
}

/* ---- building ---- */

static mt_err put_certs(mt_tlv_wr *w, mt_span noc, mt_span icac)
{
    mt_err e = mt_tlv_start(w, mt_tlv_anon(), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_bytes(w, mt_tlv_ctx(1), noc);
    if (!e && icac.len) e = mt_tlv_put_bytes(w, mt_tlv_ctx(2), icac);
    return e;
}

static mt_err finish(mt_tlv_wr *w, mt_err e, mt_span *out)
{
    if (!e) e = mt_tlv_end(w);
    return e ? e : mt_tlv_wr_done(w, out);
}

mt_err case_build_tbs(mt_span noc, mt_span icac, const uint8_t sender_eph[MT_P256_POINT_LEN],
                      const uint8_t receiver_eph[MT_P256_POINT_LEN], mt_buf out, mt_span *tbs)
{
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, out);
    mt_err e = put_certs(&w, noc, icac);
    if (!e) e = mt_tlv_put_bytes(&w, mt_tlv_ctx(3), mt_span_of(sender_eph, MT_P256_POINT_LEN));
    if (!e) e = mt_tlv_put_bytes(&w, mt_tlv_ctx(4), mt_span_of(receiver_eph, MT_P256_POINT_LEN));
    return finish(&w, e, tbs);
}

mt_err case_build_tbe2(mt_span noc, mt_span icac, const uint8_t sig[MT_P256_SIG_LEN],
                       const uint8_t resumption_id[MT_CASE_RESUMPTION_ID_LEN], mt_buf out, mt_span *tbe)
{
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, out);
    mt_err e = put_certs(&w, noc, icac);
    if (!e) e = mt_tlv_put_bytes(&w, mt_tlv_ctx(3), mt_span_of(sig, MT_P256_SIG_LEN));
    if (!e) e = mt_tlv_put_bytes(&w, mt_tlv_ctx(4), mt_span_of(resumption_id, MT_CASE_RESUMPTION_ID_LEN));
    return finish(&w, e, tbe);
}

mt_err case_build_sigma2(const uint8_t random[CASE_RANDOM_LEN], uint16_t session_id,
                         const uint8_t eph_pub[MT_P256_POINT_LEN], mt_span encrypted2, const mt_sc_params *params,
                         mt_buf out, mt_span *sigma2)
{
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, out);
    mt_err e = mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(random, CASE_RANDOM_LEN));
    if (!e) e = mt_tlv_put_u(&w, mt_tlv_ctx(2), session_id);
    if (!e) e = mt_tlv_put_bytes(&w, mt_tlv_ctx(3), mt_span_of(eph_pub, MT_P256_POINT_LEN));
    if (!e) e = mt_tlv_put_bytes(&w, mt_tlv_ctx(4), encrypted2);
    if (!e) e = mt_sc_params_put(&w, 5, params);
    return finish(&w, e, sigma2);
}
