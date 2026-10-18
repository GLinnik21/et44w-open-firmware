/* Host tests for matter-pase. Vector sources:
 *  - SPAKE2+ P256-SHA256-HKDF-HMAC (RFC 9383): connectedhomeip SPAKE2P_RFC_test_vectors.h (see
 *    spake2p_rfc_vectors.h), all four identity variants: X, Y, Z, V, Ka, Ke, cA, cB and the transcript.
 *  - Passcode 123456, salt 04a1d2c611f0bd367867797bfe823600, 2000 iterations: PBKDF2 output (w0s||w1s)
 *    from a chip-tool run, as recorded in rs-matter sc/pase/spake2p.rs test_pbkdf2.
 *  - The full PASE exchange runs against an initiator test double (prover side, w0 and w1) written
 *    here from the spec; the responder's random scalar comes from the DRBG, so the exchange is
 *    checked for agreement (cB verifies, cA is accepted, both derive the same keys), not for bytes.
 */
#include <stdio.h>
#include <string.h>

#include "mt_pase.h"
#include "mt_pase_spake.h"
#include "mt_tlv.h"
#include "spake2p_rfc_vectors.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define SC MT_P256_SCALAR_LEN
#define PT MT_P256_POINT_LEN

static int counter_entropy(void *ctx, uint8_t *out, size_t len)
{
    uint8_t *c = ctx;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)((*c)++ * 37 + 11);
    return 0;
}

/* ---------------- SPAKE2+ math against the official vectors ---------------- */

static void test_rfc_vectors(void)
{
    uint8_t ent = 1;
    mt_rng rng;
    CHECK(mt_rng_init(&rng, counter_entropy, &ent) == MT_OK);
    for (size_t i = 0; i < sizeof rfc_tvs / sizeof rfc_tvs[0]; i++) {
        const struct spake2p_rfc_tv *t = rfc_tvs[i];
        uint8_t pb[PT], z[PT], v[PT], tt[32], xg[PT], w0m[PT], pa[PT];
        mt_spake_keys k;

        /* prover share X = x*G + w0*M */
        CHECK(mt_crypto_p256_point_mul(&rng, t->x, NULL, xg) == MT_OK);
        CHECK(mt_crypto_p256_point_mul(&rng, t->w0, mt_spake_M, w0m) == MT_OK);
        CHECK(mt_crypto_p256_point_add(xg, w0m, pa) == MT_OK);
        CHECK(memcmp(pa, t->X, PT) == 0);

        /* verifier: Y, Z, V from X, y, w0, L */
        CHECK(mt_spake_verifier_points(&rng, t->w0, t->L, t->X, t->y, pb, z, v) == MT_OK);
        CHECK(memcmp(pb, t->Y, PT) == 0);
        CHECK(memcmp(z, t->Z, PT) == 0);
        CHECK(memcmp(v, t->V, PT) == 0);

        /* transcript and key schedule: Ka || Ke = H(TT) */
        mt_spake_transcript(mt_span_of(t->context, t->context_len), mt_span_of(t->prover_identity, t->prover_identity_len),
                            mt_span_of(t->verifier_identity, t->verifier_identity_len), t->X, t->Y, t->Z, t->V,
                            t->w0, tt);
        CHECK(memcmp(tt, t->Ka, 16) == 0);
        CHECK(memcmp(tt + 16, t->Ke, 16) == 0);
        CHECK(mt_spake_confirm(tt, t->X, t->Y, &k) == MT_OK);
        CHECK(memcmp(k.ke, t->Ke, 16) == 0);
        CHECK(memcmp(k.ca, t->MAC_KcA, 32) == 0);
        CHECK(memcmp(k.cb, t->MAC_KcB, 32) == 0);

        /* an off-curve X is refused */
        uint8_t bad[PT];
        memcpy(bad, t->X, PT);
        bad[PT - 1] ^= 1;
        CHECK(mt_spake_verifier_points(&rng, t->w0, t->L, bad, t->y, pb, z, v) != MT_OK);
    }
    mt_rng_free(&rng);
}

/* ---------------- initiator (prover) test double ---------------- */

typedef struct {
    uint8_t w0[SC], w1[SC], x[SC], pa[PT];
    uint8_t ke[16];
} prover;

static void prover_start(prover *pr, mt_rng *rng, const uint8_t w0[SC], const uint8_t w1[SC])
{
    uint8_t xg[PT], w0m[PT], raw[40];
    memcpy(pr->w0, w0, SC);
    memcpy(pr->w1, w1, SC);
    mt_rng_fill(rng, raw, sizeof raw);
    mt_crypto_p256_scalar_reduce(mt_span_of(raw, sizeof raw), pr->x);
    mt_crypto_p256_point_mul(rng, pr->x, NULL, xg);
    mt_crypto_p256_point_mul(rng, pr->w0, mt_spake_M, w0m);
    mt_crypto_p256_point_add(xg, w0m, pr->pa);
}

/* Z = x*(Y - w0*N), V = w1*(Y - w0*N); verifies cB and returns cA. */
static mt_err prover_finish(prover *pr, mt_rng *rng, const uint8_t ctx_hash[32], const uint8_t pb[PT],
                            const uint8_t cb[32], uint8_t ca_out[32])
{
    uint8_t nw0[SC], w0n[PT], t[PT], z[PT], v[PT], tt[32];
    mt_spake_keys k;
    mt_span none = mt_span_of("", 0);
    mt_crypto_p256_scalar_neg(pr->w0, nw0);
    mt_crypto_p256_point_mul(rng, nw0, mt_spake_N, w0n);
    mt_err e = mt_crypto_p256_point_add(pb, w0n, t);
    if (e) return e;
    mt_crypto_p256_point_mul(rng, pr->x, t, z);
    mt_crypto_p256_point_mul(rng, pr->w1, t, v);
    mt_spake_transcript(mt_span_of(ctx_hash, 32), none, none, pr->pa, pb, z, v, pr->w0, tt);
    mt_spake_confirm(tt, pr->pa, pb, &k);
    memcpy(pr->ke, k.ke, 16);
    memcpy(ca_out, k.ca, 32);
    return memcmp(k.cb, cb, 32) == 0 ? MT_OK : MT_ERR_CRYPTO;
}

/* ---------------- message helpers ---------------- */

static const uint8_t SALT[16] = { 0x04, 0xa1, 0xd2, 0xc6, 0x11, 0xf0, 0xbd, 0x36, 0x78, 0x67, 0x79, 0x7b, 0xfe, 0x82, 0x36, 0x00 };
/* w0s || w1s (2 x 40 bytes) for passcode 123456, SALT, 2000 iterations. */
static const uint8_t W0S_W1S[80] = {
    0xc7, 0x89, 0x33, 0x9c, 0xc5, 0xeb, 0xbc, 0xf6, 0xdf, 0x04, 0xa9, 0x11, 0x11, 0x06, 0x4c, 0x15, 0xac, 0x5a, 0xea, 0x67,
    0x69, 0x9f, 0x32, 0x62, 0xcf, 0xc6, 0xe9, 0x19, 0xe8, 0xa4, 0x0b, 0xb3, 0x42, 0xe8, 0xc6, 0x8e, 0xa9, 0x9a, 0x73, 0xe2,
    0x59, 0xd1, 0x17, 0xd8, 0xed, 0xcb, 0x72, 0x8c, 0xbf, 0x3b, 0xa9, 0x88, 0x02, 0xd8, 0x45, 0x4b, 0xd0, 0x2d, 0xe5, 0xe4,
    0x1c, 0xc3, 0xd7, 0x00, 0x03, 0x3c, 0x86, 0x20, 0x9a, 0x42, 0x5f, 0x55, 0x96, 0x3b, 0x9f, 0x6f, 0x79, 0xef, 0xcb, 0x37 };

typedef struct {
    mt_rng rng, drng; /* responder's and the test's own */
    uint8_t ent, dent;
    uint8_t w0[SC], w1[SC];
    mt_pase_config cfg;
    mt_pase p;
    uint8_t buf[512];
} env;

static void env_init(env *e, int with_params)
{
    memset(e, 0, sizeof *e);
    e->ent = 1;
    e->dent = 200;
    mt_rng_init(&e->rng, counter_entropy, &e->ent);
    mt_rng_init(&e->drng, counter_entropy, &e->dent);
    mt_crypto_p256_scalar_reduce(mt_span_of(W0S_W1S, 40), e->w0);
    mt_crypto_p256_scalar_reduce(mt_span_of(W0S_W1S + 40, 40), e->w1);
    memcpy(e->cfg.w0, e->w0, SC);
    mt_crypto_p256_point_mul(&e->drng, e->w1, NULL, e->cfg.l);
    e->cfg.salt = mt_span_of(SALT, sizeof SALT);
    e->cfg.iterations = 2000;
    e->cfg.session_id = 0x1234;
    if (with_params) {
        e->cfg.params.idle_ms = 500;
        e->cfg.params.active_ms = 300;
        e->cfg.params.active_threshold_ms = 4000;
        e->cfg.params.data_model_revision = 17;
        e->cfg.params.im_revision = 11;
        e->cfg.params.specification_version = 0x01030000;
        e->cfg.params.max_paths_per_invoke = 1;
    }
    mt_pase_init(&e->p, &e->cfg, &e->rng);
}

static void env_free(env *e)
{
    mt_rng_free(&e->rng);
    mt_rng_free(&e->drng);
}

static const uint8_t IRAND[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                   17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

typedef struct { size_t rand_len; int has_params, passcode_id, peer_params, unknown_field, drop_field; } req_opt;

static size_t build_req(uint8_t *buf, size_t cap, const req_opt *o)
{
    mt_tlv_wr w;
    mt_span done;
    mt_tlv_wr_init(&w, mt_buf_of(buf, cap));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    if (o->drop_field != 1) mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(IRAND, o->rand_len));
    if (o->drop_field != 2) mt_tlv_put_u(&w, mt_tlv_ctx(2), 0xBEEF);
    if (o->drop_field != 3) mt_tlv_put_u(&w, mt_tlv_ctx(3), (uint64_t)o->passcode_id);
    if (o->drop_field != 4) mt_tlv_put_bool(&w, mt_tlv_ctx(4), o->has_params != 0);
    if (o->peer_params) {
        mt_tlv_start(&w, mt_tlv_ctx(5), MT_TLV_STRUCT);
        mt_tlv_put_u(&w, mt_tlv_ctx(1), 5000);
        mt_tlv_put_u(&w, mt_tlv_ctx(2), 300);
        mt_tlv_put_u(&w, mt_tlv_ctx(3), 4000);
        mt_tlv_put_u(&w, mt_tlv_ctx(4), 17); /* an extra field we ignore */
        mt_tlv_end(&w);
    }
    if (o->unknown_field) mt_tlv_put_u(&w, mt_tlv_ctx(9), 7);
    mt_tlv_end(&w);
    return mt_tlv_wr_done(&w, &done) == MT_OK ? done.len : 0;
}

static const req_opt GOOD = { 32, 0, 0, 0, 0, 0 };

static size_t build_bytes1(uint8_t *buf, size_t cap, const uint8_t *b, size_t n)
{
    mt_tlv_wr w;
    mt_span done;
    mt_tlv_wr_init(&w, mt_buf_of(buf, cap));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(b, n));
    mt_tlv_end(&w);
    return mt_tlv_wr_done(&w, &done) == MT_OK ? done.len : 0;
}

static void ctx_hash(mt_span req, mt_span resp, uint8_t out[32])
{
    mt_sha256 s;
    mt_sha256_begin(&s);
    mt_sha256_update(&s, mt_span_of("CHIP PAKE V1 Commissioning", 26));
    mt_sha256_update(&s, req);
    mt_sha256_update(&s, resp);
    mt_sha256_finish(&s, out);
}

typedef struct {
    mt_span irand, rrand, salt;
    uint64_t session_id, iterations;
    int has_pbkdf, has_params;
    uint32_t idle, active, spec;
    uint64_t threshold, dm, im, paths;
    int n_params_fields;
} resp_view;

/* Independent reader for PBKDFParamResponse. */
static int read_resp(mt_span in, resp_view *v)
{
    mt_tlv_rd r;
    memset(v, 0, sizeof *v);
    mt_tlv_rd_init(&r, in);
    if (mt_tlv_next(&r) || r.type != MT_TLV_STRUCT || r.tag.kind != MT_TAG_ANON || mt_tlv_enter(&r)) return 0;
    mt_err e;
    while (!(e = mt_tlv_next(&r))) {
        if (mt_tlv_is_ctx(&r, 1)) mt_tlv_get_bytes(&r, &v->irand);
        else if (mt_tlv_is_ctx(&r, 2)) mt_tlv_get_bytes(&r, &v->rrand);
        else if (mt_tlv_is_ctx(&r, 3)) mt_tlv_get_u64(&r, &v->session_id);
        else if (mt_tlv_is_ctx(&r, 4)) {
            v->has_pbkdf = 1;
            mt_tlv_enter(&r);
            while (!mt_tlv_next(&r)) {
                if (mt_tlv_is_ctx(&r, 1)) mt_tlv_get_u64(&r, &v->iterations);
                if (mt_tlv_is_ctx(&r, 2)) mt_tlv_get_bytes(&r, &v->salt);
            }
            mt_tlv_exit(&r);
        } else if (mt_tlv_is_ctx(&r, 5)) {
            v->has_params = 1;
            mt_tlv_enter(&r);
            while (!mt_tlv_next(&r)) {
                uint64_t x;
                mt_tlv_get_u64(&r, &x);
                v->n_params_fields++;
                switch (r.tag.num) {
                case 1: v->idle = (uint32_t)x; break;
                case 2: v->active = (uint32_t)x; break;
                case 3: v->threshold = x; break;
                case 4: v->dm = x; break;
                case 5: v->im = x; break;
                case 6: v->spec = (uint32_t)x; break;
                case 7: v->paths = x; break;
                }
            }
            mt_tlv_exit(&r);
        }
    }
    return e == MT_ERR_NOT_FOUND;
}

static int is_failure_report(const env *e, mt_pase_reply rep)
{
    static const uint8_t want[8] = { 1, 0, 0, 0, 0, 0, 2, 0 }; /* FAILURE, SC, INVALID_PARAMETER */
    return rep.opcode == MT_PASE_OP_STATUS && rep.len == 8 && memcmp(e->buf, want, 8) == 0;
}

/* ---------------- tests ---------------- */

static void test_param_response(void)
{
    env e;
    uint8_t req[128];
    resp_view v;
    mt_pase_reply rep;
    env_init(&e, 1);
    req_opt o = GOOD;
    o.peer_params = 1;
    o.unknown_field = 1;
    size_t n = build_req(req, sizeof req, &o);
    CHECK(n > 0);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_OK);
    CHECK(rep.opcode == MT_PASE_OP_PARAM_RESP && rep.len > 0);
    CHECK(e.p.state == MT_PASE_WAIT_PAKE1);
    CHECK(e.p.peer_session_id == 0xBEEF);
    CHECK(e.p.peer.idle_ms == 5000 && e.p.peer.active_ms == 300 && e.p.peer.active_threshold_ms == 4000);
    CHECK(read_resp(mt_span_of(e.buf, rep.len), &v));
    CHECK(v.irand.len == 32 && memcmp(v.irand.p, IRAND, 32) == 0);
    CHECK(v.rrand.len == 32 && memcmp(v.rrand.p, IRAND, 32) != 0);
    CHECK(v.session_id == 0x1234);
    CHECK(v.has_pbkdf && v.iterations == 2000 && v.salt.len == 16 && memcmp(v.salt.p, SALT, 16) == 0);
    CHECK(v.has_params && v.n_params_fields == 7);
    CHECK(v.idle == 500 && v.active == 300 && v.threshold == 4000 && v.dm == 17 && v.im == 11);
    CHECK(v.spec == 0x01030000 && v.paths == 1);
    /* exact encoding of the head: struct, tag1 bytes(32) */
    CHECK(e.buf[0] == 0x15 && e.buf[1] == 0x30 && e.buf[2] == 0x01 && e.buf[3] == 32);
    /* the context hash covers the exact request and response bytes */
    uint8_t want[32];
    ctx_hash(mt_span_of(req, n), mt_span_of(e.buf, rep.len), want);
    CHECK(memcmp(e.p.ctx_hash, want, 32) == 0);
    env_free(&e);
}

static void test_param_response_variants(void)
{
    env e;
    uint8_t req[128];
    resp_view v;
    mt_pase_reply rep;
    /* initiator already has the PBKDF parameters: tag 4 left out; no session params when all zero */
    env_init(&e, 0);
    req_opt o = GOOD;
    o.has_params = 1;
    size_t n = build_req(req, sizeof req, &o);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_OK);
    CHECK(read_resp(mt_span_of(e.buf, rep.len), &v));
    CHECK(!v.has_pbkdf && !v.has_params && v.session_id == 0x1234);
    CHECK(e.p.peer.idle_ms == 0);
    env_free(&e);
    /* a PBKDFParamResponse with parameters but no MRP section */
    env_init(&e, 0);
    n = build_req(req, sizeof req, &GOOD);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_OK);
    CHECK(read_resp(mt_span_of(e.buf, rep.len), &v));
    CHECK(v.has_pbkdf && !v.has_params);
    env_free(&e);
}

static void test_bad_requests(void)
{
    uint8_t req[128];
    mt_pase_reply rep;
    env e;
    for (int i = 0; i < 8; i++) {
        env_init(&e, 0);
        req_opt o = GOOD;
        size_t n;
        switch (i) {
        case 0: o.rand_len = 31; break;
        case 1: o.rand_len = 16; break;
        case 2: o.passcode_id = 1; break;
        case 3: o.drop_field = 1; break;
        case 4: o.drop_field = 2; break;
        case 5: o.drop_field = 3; break;
        case 6: o.drop_field = 4; break;
        default: break;
        }
        n = build_req(req, sizeof req, &o);
        if (i == 7) n -= 3; /* truncated */
        mt_err r = mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(e.buf, sizeof e.buf), &rep);
        CHECK(r == MT_ERR_INVALID);
        CHECK(is_failure_report(&e, rep));
        CHECK(e.p.state == MT_PASE_FAILED);
        env_free(&e);
    }
    /* garbage and empty payloads */
    env_init(&e, 0);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of("", 0), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_ERR_INVALID);
    CHECK(e.p.state == MT_PASE_FAILED);
    env_free(&e);
    env_init(&e, 0);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of("\xff\x00\x01", 3), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_ERR_INVALID);
    env_free(&e);
}

static void test_state_errors(void)
{
    uint8_t req[128], p1[100];
    mt_pase_reply rep;
    env e;
    size_t n = build_req(req, sizeof req, &GOOD);
    uint8_t fake[PT] = { 4 };
    size_t m = build_bytes1(p1, sizeof p1, fake, PT);
    /* Pake1 before PBKDFParamRequest */
    env_init(&e, 0);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PAKE1, mt_span_of(p1, m), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_ERR_STATE);
    CHECK(is_failure_report(&e, rep) && e.p.state == MT_PASE_FAILED);
    /* once failed, nothing is processed and nothing is sent */
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_ERR_STATE);
    CHECK(rep.len == 0 && e.p.state == MT_PASE_FAILED);
    mt_pase_session s;
    CHECK(mt_pase_session_keys(&e.p, &s) == MT_ERR_STATE);
    /* a reset machine accepts a fresh attempt */
    mt_pase_reset(&e.p);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_OK);
    /* a second PBKDFParamRequest while waiting for Pake1 */
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_ERR_STATE);
    env_free(&e);
    /* Pake3 straight after the request */
    env_init(&e, 0);
    mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(e.buf, sizeof e.buf), &rep);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PAKE3, mt_span_of(p1, m), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_ERR_STATE);
    env_free(&e);
}

static void test_buffers(void)
{
    uint8_t req[128], small[16];
    mt_pase_reply rep;
    env e;
    env_init(&e, 1);
    size_t n = build_req(req, sizeof req, &GOOD);
    /* too small for the response, big enough for the 8-byte report */
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(small, sizeof small), &rep) ==
          MT_ERR_BUFFER_TOO_SMALL);
    CHECK(rep.opcode == MT_PASE_OP_STATUS && rep.len == 8);
    CHECK(e.p.state == MT_PASE_FAILED);
    env_free(&e);
    /* not even room for the report */
    env_init(&e, 1);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(small, 4), &rep) == MT_ERR_BUFFER_TOO_SMALL);
    CHECK(rep.len == 0);
    env_free(&e);
}

typedef enum { RUN_OK, RUN_WRONG_PASSCODE, RUN_BAD_PA, RUN_SHORT_PA, RUN_BAD_CA } run_mode;

/* Drives a whole exchange; returns the error of the last step reached. */
static mt_err run_pase(env *e, run_mode mode, prover *pr, mt_pase_reply *last)
{
    uint8_t req[128], msg[128], pb[PT], cb[32], ca[32], ctx[32], resp[256];
    mt_pase_reply rep;
    size_t n = build_req(req, sizeof req, &GOOD);
    mt_err r = mt_pase_recv(&e->p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(e->buf, sizeof e->buf), &rep);
    *last = rep;
    if (r) return r;
    ctx_hash(mt_span_of(req, n), mt_span_of(e->buf, rep.len), ctx);
    memcpy(resp, e->buf, rep.len);

    uint8_t w0[SC];
    memcpy(w0, e->w0, SC);
    if (mode == RUN_WRONG_PASSCODE) w0[SC - 1] ^= 0x55;
    prover_start(pr, &e->drng, w0, e->w1);
    if (mode == RUN_BAD_PA) pr->pa[PT - 1] ^= 1;
    size_t m = build_bytes1(msg, sizeof msg, pr->pa, mode == RUN_SHORT_PA ? PT - 1 : PT);
    r = mt_pase_recv(&e->p, MT_PASE_OP_PAKE1, mt_span_of(msg, m), mt_buf_of(e->buf, sizeof e->buf), &rep);
    *last = rep;
    if (r) return r;
    CHECK(rep.opcode == MT_PASE_OP_PAKE2);

    /* Pake2 = struct { 1: pB[65], 2: cB[32] } */
    mt_tlv_rd rd;
    mt_span s;
    mt_tlv_rd_init(&rd, mt_span_of(e->buf, rep.len));
    CHECK(mt_tlv_next(&rd) == MT_OK && mt_tlv_enter(&rd) == MT_OK);
    CHECK(mt_tlv_find_ctx(&rd, 1) == MT_OK && mt_tlv_get_bytes(&rd, &s) == MT_OK && s.len == PT);
    memcpy(pb, s.p, PT);
    CHECK(mt_tlv_find_ctx(&rd, 2) == MT_OK && mt_tlv_get_bytes(&rd, &s) == MT_OK && s.len == 32);
    memcpy(cb, s.p, 32);

    r = prover_finish(pr, &e->drng, ctx, pb, cb, ca);
    if (mode == RUN_WRONG_PASSCODE) {
        CHECK(r == MT_ERR_CRYPTO); /* the prover sees the mismatch in cB too */
    } else {
        CHECK(r == MT_OK);
    }
    if (mode == RUN_BAD_CA) ca[3] ^= 1;
    m = build_bytes1(msg, sizeof msg, ca, 32);
    r = mt_pase_recv(&e->p, MT_PASE_OP_PAKE3, mt_span_of(msg, m), mt_buf_of(e->buf, sizeof e->buf), &rep);
    *last = rep;
    return r;
}

static void test_full_exchange(void)
{
    env e;
    prover pr;
    mt_pase_reply rep;
    mt_pase_session s;
    uint8_t okm[48];
    env_init(&e, 1);
    CHECK(run_pase(&e, RUN_OK, &pr, &rep) == MT_OK);
    static const uint8_t ok_report[8] = { 0 }; /* SUCCESS, Secure Channel, SESSION_ESTABLISHMENT_SUCCESS */
    CHECK(rep.opcode == MT_PASE_OP_STATUS && rep.len == 8 && memcmp(e.buf, ok_report, 8) == 0);
    CHECK(e.p.state == MT_PASE_ESTABLISHED);
    CHECK(mt_pase_session_keys(&e.p, &s) == MT_OK);
    CHECK(s.local_session_id == 0x1234 && s.peer_session_id == 0xBEEF);
    /* both sides agree: the prover's Ke through HKDF(nil, Ke, "SessionKeys") */
    CHECK(mt_crypto_hkdf_sha256(mt_span_of("", 0), mt_span_of(pr.ke, 16), mt_span_of("SessionKeys", 11),
                                mt_buf_of(okm, sizeof okm)) == MT_OK);
    CHECK(memcmp(s.i2r, okm, 16) == 0 && memcmp(s.r2i, okm + 16, 16) == 0 && memcmp(s.attestation_challenge, okm + 32, 16) == 0);
    CHECK(memcmp(s.i2r, s.r2i, 16) != 0 && memcmp(s.r2i, s.attestation_challenge, 16) != 0);
    /* the secrets of the handshake are gone once established */
    uint8_t zero[32] = { 0 };
    CHECK(memcmp(e.p.ca, zero, 32) == 0 && memcmp(e.p.ctx_hash, zero, 32) == 0);
    /* an established machine takes no more input */
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PAKE3, mt_span_of("", 0), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_ERR_STATE);
    CHECK(e.p.state == MT_PASE_ESTABLISHED);
    /* reset wipes everything and keeps the wiring */
    mt_pase_reset(&e.p);
    CHECK(e.p.state == MT_PASE_IDLE && e.p.cfg == &e.cfg && e.p.rng == &e.rng);
    uint8_t ke0[16] = { 0 };
    CHECK(memcmp(e.p.ke, ke0, 16) == 0 && mt_pase_session_keys(&e.p, &s) == MT_ERR_STATE);
    env_free(&e);
}

static void test_two_exchanges_differ(void)
{
    env e;
    prover a, b;
    mt_pase_reply rep;
    env_init(&e, 0);
    CHECK(run_pase(&e, RUN_OK, &a, &rep) == MT_OK);
    mt_pase_session s1, s2;
    mt_pase_session_keys(&e.p, &s1);
    mt_pase_reset(&e.p);
    CHECK(run_pase(&e, RUN_OK, &b, &rep) == MT_OK);
    mt_pase_session_keys(&e.p, &s2);
    CHECK(memcmp(s1.i2r, s2.i2r, 16) != 0); /* fresh y and randoms every time */
    env_free(&e);
}

static void test_failures(void)
{
    env e;
    prover pr;
    mt_pase_reply rep;
    mt_pase_session s;
    env_init(&e, 0);
    CHECK(run_pase(&e, RUN_WRONG_PASSCODE, &pr, &rep) == MT_ERR_CRYPTO);
    CHECK(is_failure_report(&e, rep) && e.p.state == MT_PASE_FAILED);
    CHECK(mt_pase_session_keys(&e.p, &s) == MT_ERR_STATE);
    env_free(&e);

    env_init(&e, 0);
    CHECK(run_pase(&e, RUN_BAD_CA, &pr, &rep) == MT_ERR_CRYPTO);
    CHECK(is_failure_report(&e, rep) && e.p.state == MT_PASE_FAILED);
    env_free(&e);

    env_init(&e, 0);
    CHECK(run_pase(&e, RUN_BAD_PA, &pr, &rep) == MT_ERR_CRYPTO);
    CHECK(is_failure_report(&e, rep) && e.p.state == MT_PASE_FAILED);
    env_free(&e);

    env_init(&e, 0);
    CHECK(run_pase(&e, RUN_SHORT_PA, &pr, &rep) == MT_ERR_INVALID);
    CHECK(is_failure_report(&e, rep));
    env_free(&e);

    /* pA = the point at infinity encoding / all zero is not a point */
    env_init(&e, 0);
    uint8_t req[128], msg[128], zero[PT] = { 0 };
    size_t n = build_req(req, sizeof req, &GOOD);
    mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(e.buf, sizeof e.buf), &rep);
    size_t m = build_bytes1(msg, sizeof msg, zero, PT);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PAKE1, mt_span_of(msg, m), mt_buf_of(e.buf, sizeof e.buf), &rep) != MT_OK);
    CHECK(is_failure_report(&e, rep));
    env_free(&e);
}

static void test_status(void)
{
    uint8_t b[8];
    size_t n = 0;
    CHECK(mt_sc_status(1, 2, mt_buf_of(b, sizeof b), &n) == MT_OK && n == 8);
    CHECK(b[0] == 1 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 2 && b[7] == 0);
    CHECK(mt_sc_status(1, 2, mt_buf_of(b, 7), &n) == MT_ERR_BUFFER_TOO_SMALL);
}


/* A StatusReport from the initiator (it gave up, e.g. after a bad Pake2) ends the attempt without a reply:
 * answering a StatusReport with another one is never correct (CASE behaves the same). */
static void test_peer_status_report(void)
{
    uint8_t req[128], st[8];
    mt_pase_reply rep;
    env e;
    size_t n = build_req(req, sizeof req, &GOOD), sl;
    CHECK(mt_sc_status(1, 2, mt_buf_of(st, sizeof st), &sl) == MT_OK);
    env_init(&e, 0);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_PARAM_REQ, mt_span_of(req, n), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_OK);
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_STATUS, mt_span_of(st, sl), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_ERR_STATE);
    CHECK(rep.len == 0 && rep.opcode == 0 && e.p.state == MT_PASE_FAILED);
    env_free(&e);
    env_init(&e, 0); /* also before anything else */
    CHECK(mt_pase_recv(&e.p, MT_PASE_OP_STATUS, mt_span_of(st, sl), mt_buf_of(e.buf, sizeof e.buf), &rep) == MT_ERR_STATE);
    CHECK(rep.len == 0 && e.p.state == MT_PASE_FAILED);
    env_free(&e);
}

int main(void)
{
    test_rfc_vectors();
    test_param_response();
    test_param_response_variants();
    test_bad_requests();
    test_state_errors();
    test_buffers();
    test_full_exchange();
    test_two_exchanges_differ();
    test_failures();
    test_status();
    test_peer_status_report();
    printf("matter-pase: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
