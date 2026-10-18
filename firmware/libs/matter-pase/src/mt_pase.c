#include "mt_pase.h"

#include <string.h>

#include "mt_pase_spake.h"
#include "mt_tlv.h"

#define SC MT_P256_SCALAR_LEN
#define PT MT_P256_POINT_LEN
#define RANDOM_LEN 32
#define GENERAL_FAILURE 1
#define CODE_INVALID_PARAMETER 2

void mt_pase_init(mt_pase *p, const mt_pase_config *cfg, mt_rng *rng)
{
    memset(p, 0, sizeof *p);
    p->cfg = cfg;
    p->rng = rng;
}

void mt_pase_reset(mt_pase *p)
{
    const mt_pase_config *cfg = p->cfg;
    mt_rng *rng = p->rng;
    mt_wipe(p, sizeof *p);
    p->cfg = cfg;
    p->rng = rng;
}

/* ---- request parsing ---- */

typedef struct {
    mt_span random;
    uint16_t session_id, passcode_id;
    bool has_params;
    mt_sc_peer_params peer;
} param_req;

/* Reads one field; returns a bit for "required fields seen". */
static mt_err parse_field(mt_tlv_rd *r, param_req *q, unsigned *seen)
{
    mt_err e = MT_OK;
    unsigned bit = 0;
    if (mt_tlv_is_ctx(r, 1)) { e = mt_tlv_get_bytes(r, &q->random); bit = 1; }
    else if (mt_tlv_is_ctx(r, 2)) { e = mt_tlv_get_u16(r, &q->session_id); bit = 2; }
    else if (mt_tlv_is_ctx(r, 3)) { e = mt_tlv_get_u16(r, &q->passcode_id); bit = 4; }
    else if (mt_tlv_is_ctx(r, 4)) { e = mt_tlv_get_bool(r, &q->has_params); bit = 8; }
    else if (mt_tlv_is_ctx(r, 5)) e = mt_sc_peer_parse(r, &q->peer);
    *seen |= bit;
    return e;
}

static mt_err parse_param_req(mt_span in, param_req *q)
{
    mt_tlv_rd r;
    unsigned seen = 0;
    mt_err e;
    memset(q, 0, sizeof *q);
    mt_tlv_rd_init(&r, in);
    if ((e = mt_tlv_next(&r)) || r.type != MT_TLV_STRUCT || (e = mt_tlv_enter(&r))) return e ? e : MT_ERR_INVALID;
    while (!(e = mt_tlv_next(&r)))
        if ((e = parse_field(&r, q, &seen))) return e;
    if (e != MT_ERR_NOT_FOUND) return e;
    return seen == 15 && q->random.len == RANDOM_LEN ? MT_OK : MT_ERR_INVALID;
}

/* Struct { 1: bytes[n] } as in Pake1 and Pake3. */
static mt_err parse_bytes1(mt_span in, size_t n, const uint8_t **out)
{
    mt_tlv_rd r;
    mt_span b;
    mt_err e;
    mt_tlv_rd_init(&r, in);
    if ((e = mt_tlv_next(&r)) || r.type != MT_TLV_STRUCT || (e = mt_tlv_enter(&r))) return e ? e : MT_ERR_INVALID;
    if ((e = mt_tlv_find_ctx(&r, 1))) return e == MT_ERR_NOT_FOUND ? MT_ERR_INVALID : e;
    if ((e = mt_tlv_get_bytes(&r, &b))) return e;
    if (b.len != n) return MT_ERR_INVALID;
    *out = b.p;
    return MT_OK;
}

/* ---- response building ---- */

static mt_err put_pbkdf(mt_tlv_wr *w, const mt_pase_config *c)
{
    mt_err e = mt_tlv_start(w, mt_tlv_ctx(4), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_u(w, mt_tlv_ctx(1), c->iterations);
    if (!e) e = mt_tlv_put_bytes(w, mt_tlv_ctx(2), c->salt);
    return e ? e : mt_tlv_end(w);
}

static mt_err build_param_resp(const mt_pase_config *c, const param_req *q, const uint8_t rnd[RANDOM_LEN],
                               mt_buf out, mt_span *resp)
{
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, out);
    mt_err e = mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_bytes(&w, mt_tlv_ctx(1), q->random);
    if (!e) e = mt_tlv_put_bytes(&w, mt_tlv_ctx(2), mt_span_of(rnd, RANDOM_LEN));
    if (!e) e = mt_tlv_put_u(&w, mt_tlv_ctx(3), c->session_id);
    if (!e && !q->has_params) e = put_pbkdf(&w, c);
    if (!e) e = mt_sc_params_put(&w, 5, &c->params);
    if (!e) e = mt_tlv_end(&w);
    return e ? e : mt_tlv_wr_done(&w, resp);
}

/* ---- the three steps ---- */

static mt_err on_param_req(mt_pase *p, mt_span payload, mt_buf out, mt_pase_reply *rep)
{
    static const char prefix[] = "CHIP PAKE V1 Commissioning";
    param_req q;
    uint8_t rnd[RANDOM_LEN];
    mt_span resp;
    mt_sha256 s;
    mt_err e = parse_param_req(payload, &q) ? MT_ERR_INVALID : MT_OK; /* any reader error = malformed */
    if (!e && q.passcode_id != 0) e = MT_ERR_INVALID; /* only the default passcode exists */
    if (!e) e = mt_rng_fill(p->rng, rnd, sizeof rnd);
    if (!e) e = build_param_resp(p->cfg, &q, rnd, out, &resp);
    if (e) return e;
    mt_sha256_begin(&s);
    mt_sha256_update(&s, mt_span_of(prefix, sizeof prefix - 1));
    mt_sha256_update(&s, payload);
    mt_sha256_update(&s, resp);
    mt_sha256_finish(&s, p->ctx_hash);
    p->peer_session_id = q.session_id;
    p->peer = q.peer;
    p->state = MT_PASE_WAIT_PAKE1;
    rep->opcode = MT_PASE_OP_PARAM_RESP;
    rep->len = resp.len;
    return MT_OK;
}

/* y uniform in [1, n-1]: 40 random bytes reduced mod n (bias below 2^-64). */
static mt_err random_scalar(mt_rng *rng, uint8_t y[SC])
{
    uint8_t raw[40];
    mt_err e = MT_ERR_CRYPTO;
    for (int i = 0; i < 4 && e == MT_ERR_CRYPTO; i++) {
        mt_err r = mt_rng_fill(rng, raw, sizeof raw);
        if (!r) r = mt_crypto_p256_scalar_reduce(mt_span_of(raw, sizeof raw), y);
        if (r) { e = r; break; }
        for (size_t k = 0; k < SC && e; k++)
            if (y[k]) e = MT_OK;
    }
    mt_wipe(raw, sizeof raw); /* the seed of y, on every path */
    if (e) mt_wipe(y, SC);
    return e;
}

static mt_err build_pake2(const uint8_t pb[PT], const uint8_t cb[MT_SHA256_LEN], mt_buf out, size_t *len)
{
    mt_tlv_wr w;
    mt_span done = { NULL, 0 };
    mt_tlv_wr_init(&w, out);
    mt_err e = mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(pb, PT));
    if (!e) e = mt_tlv_put_bytes(&w, mt_tlv_ctx(2), mt_span_of(cb, MT_SHA256_LEN));
    if (!e) e = mt_tlv_end(&w);
    if (!e) e = mt_tlv_wr_done(&w, &done);
    *len = done.len;
    return e;
}

static mt_err on_pake1(mt_pase *p, mt_span payload, mt_buf out, mt_pase_reply *rep)
{
    const uint8_t *pa;
    uint8_t y[SC], pb[PT], z[PT], v[PT], tt[MT_SHA256_LEN];
    mt_spake_keys k;
    const mt_pase_config *c = p->cfg;
    mt_err e = parse_bytes1(payload, PT, &pa) ? MT_ERR_INVALID : MT_OK;
    if (!e) e = random_scalar(p->rng, y);
    if (!e) e = mt_spake_verifier_points(p->rng, c->w0, c->l, pa, y, pb, z, v);
    if (!e) {
        mt_span none = mt_span_of("", 0);
        mt_spake_transcript(mt_span_of(p->ctx_hash, sizeof p->ctx_hash), none, none, pa, pb, z, v, c->w0, tt);
        e = mt_spake_confirm(tt, pa, pb, &k);
    }
    if (!e) e = build_pake2(pb, k.cb, out, &rep->len);
    if (!e) {
        memcpy(p->ke, k.ke, sizeof p->ke);
        memcpy(p->ca, k.ca, sizeof p->ca);
        mt_wipe(p->ctx_hash, sizeof p->ctx_hash);
        p->state = MT_PASE_WAIT_PAKE3;
        rep->opcode = MT_PASE_OP_PAKE2;
    }
    mt_wipe(y, sizeof y);
    mt_wipe(z, sizeof z);
    mt_wipe(v, sizeof v);
    mt_wipe(&k, sizeof k);
    return e;
}

static mt_err on_pake3(mt_pase *p, mt_span payload, mt_buf out, mt_pase_reply *rep)
{
    const uint8_t *ca;
    mt_err e = parse_bytes1(payload, MT_SHA256_LEN, &ca) ? MT_ERR_INVALID : MT_OK;
    if (e) return e;
    if (!mt_ct_eq(ca, p->ca, MT_SHA256_LEN)) return MT_ERR_CRYPTO;
    if ((e = mt_sc_status(0, 0, out, &rep->len))) return e;
    mt_wipe(p->ca, sizeof p->ca);
    p->state = MT_PASE_ESTABLISHED;
    rep->opcode = MT_SC_OP_STATUS;
    return MT_OK;
}

static mt_err dispatch(mt_pase *p, uint8_t opcode, mt_span payload, mt_buf out, mt_pase_reply *rep)
{
    if (p->state == MT_PASE_IDLE && opcode == MT_PASE_OP_PARAM_REQ) return on_param_req(p, payload, out, rep);
    if (p->state == MT_PASE_WAIT_PAKE1 && opcode == MT_PASE_OP_PAKE1) return on_pake1(p, payload, out, rep);
    if (p->state == MT_PASE_WAIT_PAKE3 && opcode == MT_PASE_OP_PAKE3) return on_pake3(p, payload, out, rep);
    return MT_ERR_STATE;
}

mt_err mt_pase_recv(mt_pase *p, uint8_t opcode, mt_span payload, mt_buf out, mt_pase_reply *reply)
{
    reply->opcode = 0;
    reply->len = 0;
    if (p->state == MT_PASE_ESTABLISHED || p->state == MT_PASE_FAILED) return MT_ERR_STATE;
    if (opcode == MT_PASE_OP_STATUS) { /* the initiator gave up: end without a reply */
        mt_pase_reset(p);
        p->state = MT_PASE_FAILED;
        return MT_ERR_STATE;
    }
    mt_err e = dispatch(p, opcode, payload, out, reply);
    if (e == MT_OK) return e;
    mt_pase_reset(p);
    p->state = MT_PASE_FAILED;
    reply->len = 0;
    if (mt_sc_status(GENERAL_FAILURE, CODE_INVALID_PARAMETER, out, &reply->len) == MT_OK)
        reply->opcode = MT_SC_OP_STATUS;
    return e;
}

mt_err mt_pase_session_keys(const mt_pase *p, mt_pase_session *out)
{
    static const char info[] = "SessionKeys";
    uint8_t okm[3 * MT_PASE_KEY_LEN];
    if (p->state != MT_PASE_ESTABLISHED) return MT_ERR_STATE;
    mt_err e = mt_crypto_hkdf_sha256(mt_span_of("", 0), mt_span_of(p->ke, sizeof p->ke),
                                     mt_span_of(info, sizeof info - 1), mt_buf_of(okm, sizeof okm));
    if (e) return e;
    memcpy(out->i2r, okm, MT_PASE_KEY_LEN);
    memcpy(out->r2i, okm + MT_PASE_KEY_LEN, MT_PASE_KEY_LEN);
    memcpy(out->attestation_challenge, okm + 2 * MT_PASE_KEY_LEN, MT_PASE_KEY_LEN);
    out->local_session_id = p->cfg->session_id;
    out->peer_session_id = p->peer_session_id;
    out->peer = p->peer;
    mt_wipe(okm, sizeof okm);
    return MT_OK;
}
