/* See mt_test_init.h. */
#include <string.h>

#include "mt_pase.h"
#include "mt_pase_spake.h"
#include "mt_test_init.h"

#define SC MT_P256_SCALAR_LEN
#define PT MT_P256_POINT_LEN
#define IM_REV 11

enum { OP_ACK = 0x10, OP_PARAM_REQ = 0x20, OP_PARAM_RESP = 0x21, OP_PAKE1 = 0x22, OP_PAKE2 = 0x23, OP_PAKE3 = 0x24,
       OP_STATUS = 0x40, OP_IM_STATUS = 0x01, OP_IM_READ = 0x02, OP_IM_REPORT = 0x05 };

static uint32_t rnd32(ti *t)
{
    uint8_t b[4];
    mt_rng_fill(&t->rng, b, 4);
    return mt_get_le32(b);
}

void ti_init(ti *t, ti_io io, mt_entropy_fn entropy, void *entropy_ctx)
{
    uint8_t b[8];
    memset(t, 0, sizeof *t);
    t->io = io;
    mt_rng_init(&t->rng, entropy, entropy_ctx);
    mt_rng_fill(&t->rng, b, 8);
    t->node_id = mt_get_le64(b) | 1;
    mt_msg_tx_init(&t->unsec_tx, rnd32(t), false);
    mt_msg_rx_init(&t->unsec_rx);
    mt_msg_rx_init(&t->sec_rx);
    t->next_xid = (uint16_t)rnd32(t);
}

void ti_free(ti *t)
{
    mt_rng_free(&t->rng);
    mt_wipe(t->enc, sizeof t->enc);
    mt_wipe(t->dec, sizeof t->dec);
}

/* ---- PBKDF2-HMAC-SHA256 ---- */
static mt_err pbkdf2(mt_span pw, mt_span salt, uint32_t iters, uint8_t *dk, size_t dk_len)
{
    uint8_t s[MT_PASE_SALT_MAX + 4], u[32], acc[32];
    if (salt.len > MT_PASE_SALT_MAX || iters == 0) return MT_ERR_INVALID;
    memcpy(s, salt.p, salt.len);
    for (uint32_t blk = 1; (blk - 1) * 32 < dk_len; blk++) {
        s[salt.len] = (uint8_t)(blk >> 24); s[salt.len + 1] = (uint8_t)(blk >> 16);
        s[salt.len + 2] = (uint8_t)(blk >> 8); s[salt.len + 3] = (uint8_t)blk;
        mt_err e = mt_crypto_hmac_sha256(pw, mt_span_of(s, salt.len + 4), u);
        if (e) return e;
        memcpy(acc, u, 32);
        for (uint32_t i = 1; i < iters; i++) {
            e = mt_crypto_hmac_sha256(pw, mt_span_of(u, 32), u);
            if (e) return e;
            for (int k = 0; k < 32; k++) acc[k] ^= u[k];
        }
        size_t off = (blk - 1) * 32, n = dk_len - off < 32 ? dk_len - off : 32;
        memcpy(dk + off, acc, n);
    }
    return MT_OK;
}

mt_err ti_passcode_to_w(mt_rng *rng, uint32_t passcode, mt_span salt, uint32_t iterations, uint8_t w0[32],
                        uint8_t w1[32], uint8_t l[65])
{
    uint8_t pw[4], dk[80];
    mt_put_le32(pw, passcode);
    mt_err e = pbkdf2(mt_span_of(pw, 4), salt, iterations, dk, sizeof dk);
    if (e) return e;
    if ((e = mt_crypto_p256_scalar_reduce(mt_span_of(dk, 40), w0))) return e;
    if ((e = mt_crypto_p256_scalar_reduce(mt_span_of(dk + 40, 40), w1))) return e;
    return l ? mt_crypto_p256_point_mul(rng, w1, NULL, l) : MT_OK;
}

/* ---- frames ---- */
size_t ti_build(ti *t, bool secure, uint16_t xid, uint8_t flags, uint16_t protocol, uint8_t opcode, mt_span payload,
                uint32_t ack_counter, uint8_t *out, size_t cap)
{
    return ti_build_ex(t, secure, xid, (uint8_t)(flags | MT_XCHG_INITIATOR), protocol, opcode, payload, ack_counter,
                       out, cap);
}

size_t ti_build_ex(ti *t, bool secure, uint16_t xid, uint8_t flags, uint16_t protocol, uint8_t opcode, mt_span payload,
                   uint32_t ack_counter, uint8_t *out, size_t cap)
{
    mt_msg_hdr h;
    mt_proto_hdr ph;
    size_t hl, pl, flen;
    uint32_t ctr;
    memset(&h, 0, sizeof h);
    memset(&ph, 0, sizeof ph);
    if (mt_msg_tx_next(secure ? &t->sec_tx : &t->unsec_tx, &ctr)) return 0;
    h.counter = ctr;
    if (secure) h.session_id = t->peer_sid;
    else { h.has_src = true; h.src = t->node_id; }
    ph.flags = flags;
    ph.opcode = opcode;
    ph.exchange_id = xid;
    ph.protocol_id = protocol;
    ph.ack_counter = ack_counter;
    if (mt_msg_hdr_encode(&h, mt_buf_of(out, cap), &hl) || mt_proto_hdr_encode(&ph, mt_buf_of(out + hl, cap - hl), &pl))
        return 0;
    if (hl + pl + payload.len + MT_CCM_TAG_LEN > cap) return 0;
    memcpy(out + hl + pl, payload.p, payload.len);
    if (!secure) return hl + pl + payload.len;
    return mt_msg_seal(t->enc, t->sec_src, &h, mt_buf_of(out, cap), hl, pl + payload.len, &flen) ? 0 : flen;
}

void ti_send_ack(ti *t)
{
    size_t n;
    if (!t->ack_owed) return;
    n = ti_build(t, t->ack_secure, t->ack_xid, MT_XCHG_ACK, 0, OP_ACK, mt_span_of("", 0), t->ack_counter, t->obuf,
                 sizeof t->obuf);
    t->ack_owed = false;
    if (n) t->io.send(t->io.ctx, t->obuf, n);
}

mt_err ti_parse(ti *t, uint8_t *frame, size_t len, ti_msg *m)
{
    mt_msg_hdr h;
    mt_proto_hdr ph;
    size_t hl, poff, plen, pl;
    mt_msg_rx *rx;
    mt_err e;
    bool secure;
    if (mt_msg_hdr_decode(mt_span_of(frame, len), &h, &hl)) return MT_ERR_INVALID;
    secure = h.session_id != 0;
    if (!secure) {
        poff = hl;
        plen = len - hl;
        rx = &t->unsec_rx;
    } else {
        if (!t->secure || h.session_id != t->local_sid) return MT_ERR_INVALID;
        if (mt_msg_open(t->dec, t->sec_peer, frame, len, &h, &poff, &plen)) return MT_ERR_CRYPTO;
        rx = &t->sec_rx;
    }
    if (mt_proto_hdr_decode(mt_span_of(frame + poff, plen), &ph, &pl)) return MT_ERR_INVALID;
    e = mt_msg_rx_accept(rx, h.counter, secure ? MT_MSG_RX_SECURE : MT_MSG_RX_UNSECURED);
    if (e == MT_ERR_DUPLICATE && (ph.flags & MT_XCHG_RELIABLE)) { /* our ack was lost: repeat it */
        t->ack_owed = true;
        t->ack_secure = secure;
        t->ack_xid = ph.exchange_id;
        t->ack_counter = h.counter;
        ti_send_ack(t);
    }
    if (e) return e;
    m->flags = ph.flags;
    m->opcode = ph.opcode;
    m->xid = ph.exchange_id;
    m->protocol = ph.protocol_id;
    m->counter = h.counter;
    m->ack_counter = ph.ack_counter;
    m->payload = mt_span_of(frame + poff + pl, plen - pl);
    m->secure = secure;
    return MT_OK;
}

static uint8_t piggyback(ti *t, bool secure, uint16_t xid)
{
    if (t->ack_owed && t->ack_xid == xid && t->ack_secure == secure) { t->ack_owed = false; return MT_XCHG_ACK; }
    return 0;
}

mt_err ti_transact(ti *t, bool secure, uint16_t xid, uint16_t protocol, uint8_t opcode, mt_span payload,
                   ti_msg *reply)
{
    uint32_t ack_ctr = t->ack_counter;
    uint8_t fl = piggyback(t, secure, xid);
    size_t flen = ti_build(t, secure, xid, (uint8_t)(MT_XCHG_RELIABLE | fl), protocol, opcode, payload, ack_ctr,
                           t->sbuf, sizeof t->sbuf);
    bool got_ack = false;
    if (!flen) return MT_ERR_BUFFER_TOO_SMALL;
    for (unsigned tries = 0; tries < TI_MAX_TRIES; tries++) {
        size_t n;
        if (!got_ack) { /* once acked the response is merely slow: keep waiting without resending */
            if (tries) t->retransmits++;
            t->io.send(t->io.ctx, t->sbuf, flen);
        }
        while ((n = t->io.recv(t->io.ctx, t->rbuf, sizeof t->rbuf, TI_WAIT_MS)) != 0) {
            ti_msg m;
            if (ti_parse(t, t->rbuf, n, &m) != MT_OK) continue;
            if (m.xid != xid || (m.flags & MT_XCHG_INITIATOR)) continue; /* another exchange, or node-initiated */
            if (m.flags & MT_XCHG_RELIABLE) {
                t->ack_owed = true;
                t->ack_secure = m.secure;
                t->ack_xid = m.xid;
                t->ack_counter = m.counter;
            }
            if (m.protocol == 0 && m.opcode == OP_ACK) { got_ack = true; continue; }
            *reply = m;
            return MT_OK;
        }
    }
    return MT_ERR_TIMEOUT;
}

void ti_send_oneway(ti *t, bool secure, uint16_t xid, uint16_t protocol, uint8_t opcode, mt_span payload)
{
    uint32_t ack_ctr = t->ack_counter;
    uint8_t fl = piggyback(t, secure, xid);
    size_t n = ti_build(t, secure, xid, fl, protocol, opcode, payload, ack_ctr, t->obuf, sizeof t->obuf);
    if (n) t->io.send(t->io.ctx, t->obuf, n);
}

/* ---- PASE ---- */
static void note_status(ti *t, const ti_msg *m)
{
    t->status_general = t->status_code = 0;
    t->status_data_len = 0;
    if (m->payload.len < 8) return;
    t->status_general = mt_get_le16(m->payload.p);
    t->status_code = mt_get_le16(m->payload.p + 6);
    t->status_data_len = m->payload.len - 8 < sizeof t->status_data ? m->payload.len - 8 : sizeof t->status_data;
    memcpy(t->status_data, m->payload.p + 8, t->status_data_len);
}

typedef struct { uint8_t w0[SC], w1[SC], x[SC], pa[PT]; uint8_t ke[16]; } prover;

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

/* Z = x*(Y - w0*N), V = w1*(Y - w0*N); checks cB and returns cA. */
static mt_err prover_finish(prover *pr, mt_rng *rng, const uint8_t ctx_hash[32], const uint8_t pb[PT],
                            const uint8_t cb[32], uint8_t ca_out[32])
{
    uint8_t nw0[SC], w0n[PT], tp[PT], z[PT], v[PT], tt[32];
    mt_spake_keys k;
    mt_span none = mt_span_of("", 0);
    mt_crypto_p256_scalar_neg(pr->w0, nw0);
    mt_crypto_p256_point_mul(rng, nw0, mt_spake_N, w0n);
    mt_err e = mt_crypto_p256_point_add(pb, w0n, tp);
    if (e) return e;
    mt_crypto_p256_point_mul(rng, pr->x, tp, z);
    mt_crypto_p256_point_mul(rng, pr->w1, tp, v);
    mt_spake_transcript(mt_span_of(ctx_hash, 32), none, none, pr->pa, pb, z, v, pr->w0, tt);
    mt_spake_confirm(tt, pr->pa, pb, &k);
    memcpy(pr->ke, k.ke, 16);
    memcpy(ca_out, k.ca, 32);
    return memcmp(k.cb, cb, 32) == 0 ? MT_OK : MT_ERR_CRYPTO;
}

static size_t put_bytes1(uint8_t *buf, size_t cap, const uint8_t *b, size_t n)
{
    mt_tlv_wr w;
    mt_span done;
    mt_tlv_wr_init(&w, mt_buf_of(buf, cap));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(b, n));
    mt_tlv_end(&w);
    return mt_tlv_wr_done(&w, &done) == MT_OK ? done.len : 0;
}

typedef struct { mt_span rrand, salt; uint64_t sid, iters; } param_resp;

static bool read_param_resp(mt_span in, param_resp *v)
{
    mt_tlv_rd r;
    mt_err e;
    memset(v, 0, sizeof *v);
    mt_tlv_rd_init(&r, in);
    if (mt_tlv_next(&r) || r.type != MT_TLV_STRUCT || mt_tlv_enter(&r)) return false;
    while (!(e = mt_tlv_next(&r))) {
        if (mt_tlv_is_ctx(&r, 2)) mt_tlv_get_bytes(&r, &v->rrand);
        else if (mt_tlv_is_ctx(&r, 3)) mt_tlv_get_u64(&r, &v->sid);
        else if (mt_tlv_is_ctx(&r, 4) && !mt_tlv_enter(&r)) {
            while (!mt_tlv_next(&r)) {
                if (mt_tlv_is_ctx(&r, 1)) mt_tlv_get_u64(&r, &v->iters);
                else if (mt_tlv_is_ctx(&r, 2)) mt_tlv_get_bytes(&r, &v->salt);
            }
            mt_tlv_exit(&r);
        }
    }
    return e == MT_ERR_NOT_FOUND && v->sid != 0 && v->salt.len >= 16 && v->iters != 0;
}

static mt_err pase_run(ti *t, uint32_t passcode, uint32_t *iterations, bool full)
{
    uint8_t req[96], resp[320], buf[160], ctx[32], ca[32], pb[PT], cb[32];
    size_t req_len, resp_len, n;
    uint8_t irand[32];
    uint16_t xid = t->next_xid++;
    ti_msg m;
    mt_tlv_wr w;
    mt_span done;
    param_resp pr;
    prover pv;
    uint8_t w0[SC], w1[SC];
    mt_err e;

    mt_rng_fill(&t->rng, irand, sizeof irand);
    do t->local_sid = (uint16_t)rnd32(t); while (t->local_sid == 0);
    mt_tlv_wr_init(&w, mt_buf_of(req, sizeof req));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(irand, sizeof irand));
    mt_tlv_put_u(&w, mt_tlv_ctx(2), t->local_sid);
    mt_tlv_put_u(&w, mt_tlv_ctx(3), 0);
    mt_tlv_put_bool(&w, mt_tlv_ctx(4), false);
    mt_tlv_end(&w);
    if (mt_tlv_wr_done(&w, &done)) return MT_ERR_INVALID;
    req_len = done.len;

    if ((e = ti_transact(t, false, xid, 0, OP_PARAM_REQ, done, &m))) return e;
    if (m.opcode == OP_STATUS) { note_status(t, &m); ti_send_ack(t); return MT_ERR_STATE; }
    if (m.opcode != OP_PARAM_RESP || m.payload.len > sizeof resp) return MT_ERR_STATE;
    memcpy(resp, m.payload.p, m.payload.len);
    resp_len = m.payload.len;
    if (!read_param_resp(mt_span_of(resp, resp_len), &pr)) return MT_ERR_INVALID;
    if (iterations) *iterations = (uint32_t)pr.iters;
    if (!full) return MT_OK;

    if ((e = ti_passcode_to_w(&t->rng, passcode, pr.salt, (uint32_t)pr.iters, w0, w1, NULL))) return e;
    {
        mt_sha256 s;
        mt_sha256_begin(&s);
        mt_sha256_update(&s, mt_span_of("CHIP PAKE V1 Commissioning", 26));
        mt_sha256_update(&s, mt_span_of(req, req_len));
        mt_sha256_update(&s, mt_span_of(resp, resp_len));
        mt_sha256_finish(&s, ctx);
    }
    prover_start(&pv, &t->rng, w0, w1);
    n = put_bytes1(buf, sizeof buf, pv.pa, PT);
    if ((e = ti_transact(t, false, xid, 0, OP_PAKE1, mt_span_of(buf, n), &m))) return e;
    if (m.opcode == OP_STATUS) { note_status(t, &m); ti_send_ack(t); return MT_ERR_STATE; }
    if (m.opcode != OP_PAKE2) return MT_ERR_STATE;
    {
        mt_tlv_rd rd;
        mt_span s;
        mt_tlv_rd_init(&rd, m.payload);
        if (mt_tlv_next(&rd) || mt_tlv_enter(&rd)) return MT_ERR_INVALID;
        if (mt_tlv_find_ctx(&rd, 1) || mt_tlv_get_bytes(&rd, &s) || s.len != PT) return MT_ERR_INVALID;
        memcpy(pb, s.p, PT);
        if (mt_tlv_find_ctx(&rd, 2) || mt_tlv_get_bytes(&rd, &s) || s.len != 32) return MT_ERR_INVALID;
        memcpy(cb, s.p, 32);
    }
    e = prover_finish(&pv, &t->rng, ctx, pb, cb, ca);
    bool mismatch = e != MT_OK;
    if (mismatch && !t->force_pake3) { /* wrong passcode (or a bad point): tell the node and give up */
        uint8_t st[8] = { 1, 0, 0, 0, 0, 0, 2, 0 }; /* FAILURE, Secure Channel, INVALID_PARAMETER */
        ti_send_oneway(t, false, xid, 0, OP_STATUS, mt_span_of(st, sizeof st));
        return MT_ERR_CRYPTO;
    }
    n = put_bytes1(buf, sizeof buf, ca, 32);
    if ((e = ti_transact(t, false, xid, 0, OP_PAKE3, mt_span_of(buf, n), &m))) return e;
    if (m.opcode != OP_STATUS) return MT_ERR_STATE;
    note_status(t, &m);
    ti_send_ack(t);
    if (t->status_general != 0 || t->status_code != 0) return mismatch ? MT_ERR_CRYPTO : MT_ERR_STATE;
    if (mismatch) return MT_ERR_CRYPTO; /* the device accepted a cA computed from the wrong passcode: never expected */
    {
        uint8_t okm[48];
        mt_err ke = mt_crypto_hkdf_sha256(mt_span_of("", 0), mt_span_of(pv.ke, 16), mt_span_of("SessionKeys", 11),
                                          mt_buf_of(okm, sizeof okm));
        if (ke) return ke;
        memcpy(t->enc, okm, 16);      /* I2R */
        memcpy(t->dec, okm + 16, 16); /* R2I */
        mt_wipe(okm, sizeof okm);
    }
    t->peer_sid = (uint16_t)pr.sid;
    t->sec_src = t->sec_peer = 0;
    mt_msg_tx_init(&t->sec_tx, rnd32(t), true);
    mt_msg_rx_init(&t->sec_rx);
    t->secure = true;
    return MT_OK;
}

mt_err ti_pase(ti *t, uint32_t passcode, uint32_t *iterations) { return pase_run(t, passcode, iterations, true); }
mt_err ti_pase_params_only(ti *t) { return pase_run(t, 0, NULL, false); }

void ti_close_session(ti *t)
{
    static const uint8_t close_report[8] = { 0, 0, 0, 0, 0, 0, 3, 0 };
    if (!t->secure) return;
    ti_send_oneway(t, true, t->next_xid++, 0, OP_STATUS, mt_span_of(close_report, sizeof close_report));
    t->secure = false;
    mt_wipe(t->enc, sizeof t->enc);
    mt_wipe(t->dec, sizeof t->dec);
}

/* ---- IM read ---- */
size_t ti_build_read_request(const ti_path *paths, size_t n_paths, uint8_t *out, size_t cap)
{
    mt_tlv_wr w;
    mt_span done;
    mt_tlv_wr_init(&w, mt_buf_of(out, cap));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_start(&w, mt_tlv_ctx(0), MT_TLV_ARRAY);
    for (size_t i = 0; i < n_paths; i++) {
        mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_LIST);
        if (paths[i].endpoint >= 0) mt_tlv_put_u(&w, mt_tlv_ctx(2), (uint64_t)paths[i].endpoint);
        if (paths[i].cluster >= 0) mt_tlv_put_u(&w, mt_tlv_ctx(3), (uint64_t)paths[i].cluster);
        if (paths[i].attr >= 0) mt_tlv_put_u(&w, mt_tlv_ctx(4), (uint64_t)paths[i].attr);
        mt_tlv_end(&w);
    }
    mt_tlv_end(&w);
    mt_tlv_put_bool(&w, mt_tlv_ctx(3), true);
    mt_tlv_put_u(&w, mt_tlv_ctx(255), IM_REV);
    mt_tlv_end(&w);
    return mt_tlv_wr_done(&w, &done) == MT_OK ? done.len : 0;
}

static void add_attr(ti_report *out, const ti_attr *a)
{
    if (out->n == TI_MAX_ATTRS) { out->overflow = true; return; }
    out->a[out->n++] = *a;
}

static void read_path(mt_tlv_rd *r, ti_attr *a)
{
    if (mt_tlv_enter(r)) return;
    while (!mt_tlv_next(r)) {
        if (mt_tlv_is_ctx(r, 2)) mt_tlv_get_u16(r, &a->endpoint);
        else if (mt_tlv_is_ctx(r, 3)) mt_tlv_get_u32(r, &a->cluster);
        else if (mt_tlv_is_ctx(r, 4)) mt_tlv_get_u32(r, &a->attr);
        else if (mt_tlv_is_ctx(r, 5)) a->list_item = true;
    }
    mt_tlv_exit(r);
}

static void read_data_value(mt_tlv_rd *r, ti_attr *a)
{
    mt_span s;
    a->type = r->type;
    if (r->type == MT_TLV_UINT || r->type == MT_TLV_SINT || r->type == MT_TLV_BOOL) {
        a->val = r->val;
    } else if (r->type == MT_TLV_UTF8 || r->type == MT_TLV_BYTES) {
        s = r->str;
        a->str_len = s.len;
        memcpy(a->str, s.p, s.len < TI_STR_MAX ? s.len : TI_STR_MAX);
    } else if (r->type == MT_TLV_ARRAY && !mt_tlv_enter(r)) {
        while (!mt_tlv_next(r)) a->val++;
        mt_tlv_exit(r);
    }
}

static void read_report_ib(mt_tlv_rd *r, ti_report *out)
{
    ti_attr a;
    memset(&a, 0, sizeof a);
    if (mt_tlv_enter(r)) return;
    while (!mt_tlv_next(r)) {
        if (mt_tlv_is_ctx(r, 0) && !mt_tlv_enter(r)) { /* AttributeStatusIB */
            a.is_status = true;
            while (!mt_tlv_next(r)) {
                if (mt_tlv_is_ctx(r, 0)) read_path(r, &a);
                else if (mt_tlv_is_ctx(r, 1) && !mt_tlv_enter(r)) {
                    while (!mt_tlv_next(r)) if (mt_tlv_is_ctx(r, 0)) mt_tlv_get_u16(r, &a.status);
                    mt_tlv_exit(r);
                }
            }
            mt_tlv_exit(r);
        } else if (mt_tlv_is_ctx(r, 1) && !mt_tlv_enter(r)) { /* AttributeDataIB */
            while (!mt_tlv_next(r)) {
                if (mt_tlv_is_ctx(r, 1)) read_path(r, &a);
                else if (mt_tlv_is_ctx(r, 2)) read_data_value(r, &a);
            }
            mt_tlv_exit(r);
        }
    }
    mt_tlv_exit(r);
    add_attr(out, &a);
}

/* ReportData: fills out, sets *more / *suppress. */
static bool parse_report(mt_span in, ti_report *out, bool *more, bool *suppress)
{
    mt_tlv_rd r;
    mt_err e;
    *more = *suppress = false;
    mt_tlv_rd_init(&r, in);
    if (mt_tlv_next(&r) || r.type != MT_TLV_STRUCT || mt_tlv_enter(&r)) return false;
    while (!(e = mt_tlv_next(&r))) {
        if (mt_tlv_is_ctx(&r, 1) && !mt_tlv_enter(&r)) {
            while (!mt_tlv_next(&r)) read_report_ib(&r, out);
            mt_tlv_exit(&r);
        } else if (mt_tlv_is_ctx(&r, 3)) mt_tlv_get_bool(&r, more);
        else if (mt_tlv_is_ctx(&r, 4)) mt_tlv_get_bool(&r, suppress);
    }
    return e == MT_ERR_NOT_FOUND;
}

static uint16_t parse_status_resp(mt_span in)
{
    mt_tlv_rd r;
    uint16_t st = 0xFFFF;
    mt_tlv_rd_init(&r, in);
    if (mt_tlv_next(&r) || mt_tlv_enter(&r)) return st;
    if (!mt_tlv_find_ctx(&r, 0)) mt_tlv_get_u16(&r, &st);
    return st;
}

mt_err ti_read(ti *t, const ti_path *paths, size_t n_paths, ti_report *out)
{
    uint8_t rq[256], sr[16];
    size_t rq_len = ti_build_read_request(paths, n_paths, rq, sizeof rq), sr_len;
    uint16_t xid = t->next_xid++;
    ti_msg m;
    mt_tlv_wr w;
    mt_span done;
    mt_err e;
    bool more, suppress;

    memset(out, 0, sizeof *out);
    if (!t->secure || !rq_len) return MT_ERR_STATE;
    mt_tlv_wr_init(&w, mt_buf_of(sr, sizeof sr));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_u(&w, mt_tlv_ctx(0), 0);
    mt_tlv_put_u(&w, mt_tlv_ctx(255), IM_REV);
    mt_tlv_end(&w);
    mt_tlv_wr_done(&w, &done);
    sr_len = done.len;

    e = ti_transact(t, true, xid, 1, OP_IM_READ, mt_span_of(rq, rq_len), &m);
    for (;;) {
        if (e) return e;
        if (m.opcode == OP_IM_STATUS) { out->error_status = parse_status_resp(m.payload); ti_send_ack(t); return MT_ERR_STATE; }
        if (m.opcode != OP_IM_REPORT) return MT_ERR_STATE;
        out->chunks++;
        if (!parse_report(m.payload, out, &more, &suppress)) return MT_ERR_INVALID;
        if (!more) {
            if (!suppress) ti_send_oneway(t, true, xid, 1, OP_IM_STATUS, mt_span_of(sr, sr_len));
            ti_send_ack(t);
            return MT_OK;
        }
        e = ti_transact(t, true, xid, 1, OP_IM_STATUS, mt_span_of(sr, sr_len), &m);
    }
}

const ti_attr *ti_find(const ti_report *r, uint16_t endpoint, uint32_t cluster, uint32_t attr)
{
    for (size_t i = 0; i < r->n; i++) {
        const ti_attr *a = &r->a[i];
        if (!a->is_status && !a->list_item && a->endpoint == endpoint && a->cluster == cluster && a->attr == attr) return a;
    }
    return NULL;
}
