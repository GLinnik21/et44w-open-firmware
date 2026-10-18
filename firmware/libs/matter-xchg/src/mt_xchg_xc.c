/* Exchange table, transmit path, MRP timers (spec 4.12). */
#include "mt_xchg_priv.h"

#define ACK_FRAME_MAX (MT_MSG_HDR_MAX + MT_PROTO_HDR_MAX + MT_CCM_TAG_LEN)

void mt_xchg_init(mt_xchg *m, const mt_xchg_ports *ports)
{
    memset(m, 0, sizeof *m);
    m->p = *ports;
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++) m->xc[i].txbuf = -1;
    mt_msg_tx_init(&m->unsec_tx, xc_random32(m), false);
    m->next_xchg_id = (uint16_t)xc_random32(m);
}

mt_err mt_xchg_register(mt_xchg *m, const mt_xchg_proto *p)
{
    size_t free_slot = MT_XCHG_N_PROTOS;
    for (size_t i = 0; i < MT_XCHG_N_PROTOS; i++) {
        if (!m->protos[i]) { if (free_slot == MT_XCHG_N_PROTOS) free_slot = i; }
        else if (m->protos[i]->protocol_id == p->protocol_id) return MT_ERR_INVALID;
    }
    if (free_slot == MT_XCHG_N_PROTOS) return MT_ERR_BUFFER_TOO_SMALL;
    m->protos[free_slot] = p;
    return MT_OK;
}

const mt_xchg_proto *xc_find_proto(const mt_xchg *m, uint16_t protocol_id)
{
    for (size_t i = 0; i < MT_XCHG_N_PROTOS; i++)
        if (m->protos[i] && m->protos[i]->protocol_id == protocol_id) return m->protos[i];
    return NULL;
}

void mt_xchg_set_session_cb(mt_xchg *m, mt_xchg_session_cb cb, void *ctx) { m->on_session_close = cb; m->session_cb_ctx = ctx; }
void mt_xchg_set_commissioning(mt_xchg *m, bool open) { m->commissioning = open; }

/* ---- MRP timing ---- */
uint32_t mt_xchg_backoff_ms(uint32_t base_ms, unsigned n, uint8_t rnd)
{
    uint64_t t = (uint64_t)base_ms * 11 / 10; /* MRP_BACKOFF_MARGIN 1.1 */
    for (unsigned i = 1; i < n; i++) t = t * 16 / 10; /* MRP_BACKOFF_BASE 1.6, threshold 1 */
    t += t * rnd / 1024;                              /* jitter: up to +0.25 */
    return t < UINT32_MAX ? (uint32_t)t : UINT32_MAX;  /* saturates, never wraps to a short delay */
}

/* Interval used while waiting for an ack: the peer's active interval if we heard it recently. */
static uint32_t retx_wait(mt_xchg *m, const mt_xchg_session *s, unsigned n, uint32_t now)
{
    uint8_t r;
    uint32_t base = (now - s->last_rx) < MT_XCHG_ACTIVE_THRESHOLD_MS ? s->active_ms : s->idle_ms;
    m->p.random(m->p.ctx, &r, 1);
    return mt_xchg_backoff_ms(base, n, r);
}

/* ---- frame buffers ---- */
static int txbuf_get(mt_xchg *m)
{
    for (int i = 0; i < MT_XCHG_N_TXBUF; i++)
        if (!m->txbuf_used[i]) { m->txbuf_used[i] = true; return i; }
    return -1;
}

static void txbuf_put(mt_xchg *m, int i) { if (i >= 0) m->txbuf_used[i] = false; }

/* ---- exchange table ---- */
mt_xchg_xchg *xc_find(mt_xchg *m, const mt_xchg_session *s, uint16_t id, bool initiator)
{
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++) {
        mt_xchg_xchg *x = &m->xc[i];
        if (x->used && x->session == s && x->id == id && x->initiator == initiator) return x;
    }
    return NULL;
}

bool xc_have_free(const mt_xchg *m)
{
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++) if (!m->xc[i].used) return true;
    return false;
}

mt_xchg_xchg *xc_alloc(mt_xchg *m, mt_xchg_session *s, uint16_t id, bool initiator, const mt_xchg_proto *p)
{
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++) {
        mt_xchg_xchg *x = &m->xc[i];
        if (x->used) continue;
        memset(x, 0, sizeof *x);
        x->used = true;
        x->initiator = initiator;
        x->txbuf = -1;
        x->id = id;
        x->session = s;
        x->proto = p;
        x->last_activity = xc_now(m);
        return x;
    }
    return NULL;
}

/* Re-entrant: an on_close that closes the exchange's session reaches here again for the same exchange, which then
 * returns at once, so on_close runs once per exchange. */
void xc_free(mt_xchg *m, mt_xchg_xchg *xc, mt_xchg_end why)
{
    if (xc->freeing) return;
    xc->freeing = true;
    txbuf_put(m, xc->txbuf);
    xc->txbuf = -1;
    xc->closing = true; /* the callback can no longer send on it */
    xc->ack_pending = false;
    if (why && xc->proto->on_close) xc->proto->on_close(xc->proto->ctx, xc, why);
    xc->used = false;
    xc->freeing = false;
}

/* ---- transmit ---- */
/* Encodes one frame for s into buf[0, cap) and seals it. The tx counter is only consumed once it fits. */
static mt_err build(mt_xchg *m, mt_xchg_session *s, uint8_t *buf, size_t cap, const mt_proto_hdr *ph, mt_span payload,
                    size_t *len, uint32_t *counter)
{
    bool sec = xc_secure(s);
    mt_msg_hdr h;
    size_t hl, pl;
    mt_err e;
    if (cap < MT_MSG_HDR_MAX + MT_PROTO_HDR_MAX + MT_CCM_TAG_LEN ||
        payload.len > cap - MT_MSG_HDR_MAX - MT_PROTO_HDR_MAX - MT_CCM_TAG_LEN)
        return MT_ERR_BUFFER_TOO_SMALL;
    e = mt_msg_tx_next(sec ? &s->tx : &m->unsec_tx, counter);
    if (e != MT_OK) return e;
    memset(&h, 0, sizeof h);
    h.counter = *counter;
    if (sec) h.session_id = s->peer_id;
    else { h.dsiz = MT_MSG_DSIZ_NODE; h.dst = s->peer_node; } /* unsecured reply names the initiator */
    e = mt_msg_hdr_encode(&h, mt_buf_of(buf, cap), &hl);
    if (e != MT_OK) return e;
    e = mt_proto_hdr_encode(ph, mt_buf_of(buf + hl, cap - hl), &pl);
    if (e != MT_OK) return e;
    if (payload.len) memcpy(buf + hl + pl, payload.p, payload.len); /* payload.p may be NULL when empty */
    if (!sec) { *len = hl + pl + payload.len; return MT_OK; }
    return mt_msg_seal(s->enc_key, s->local_node, &h, mt_buf_of(buf, cap), hl, pl + payload.len, len);
}

static void emit(mt_xchg *m, mt_xchg_session *s, const uint8_t *buf, size_t len)
{
    s->last_activity = xc_now(m);
    m->p.send(m->p.ctx, (mt_xchg_transport)s->transport, &s->addr, mt_span_of(buf, len));
}

void xc_send_ack(mt_xchg *m, mt_xchg_session *s, uint16_t id, bool we_initiated, uint32_t ack_counter)
{
    uint8_t buf[ACK_FRAME_MAX];
    mt_proto_hdr ph;
    size_t len;
    uint32_t ctr;
    memset(&ph, 0, sizeof ph);
    ph.flags = (uint8_t)(MT_XCHG_ACK | (we_initiated ? MT_XCHG_INITIATOR : 0));
    ph.opcode = MT_XCHG_OP_STANDALONE_ACK;
    ph.exchange_id = id;
    ph.protocol_id = MT_XCHG_PROTO_SECURE_CHANNEL;
    ph.ack_counter = ack_counter;
    if (build(m, s, buf, sizeof buf, &ph, mt_span_of(NULL, 0), &len, &ctr) == MT_OK) emit(m, s, buf, len);
}

mt_err mt_xchg_open(mt_xchg *m, mt_xchg_session *s, uint16_t protocol_id, mt_xchg_xchg **out)
{
    const mt_xchg_proto *p = xc_find_proto(m, protocol_id);
    mt_xchg_xchg *x;
    uint16_t id;
    if (!xc_secure(s)) return MT_ERR_INVALID;
    if (!p) return MT_ERR_NOT_FOUND;
    do id = m->next_xchg_id++; while (xc_find(m, s, id, true));
    x = xc_alloc(m, s, id, true, p);
    if (!x) return MT_ERR_BUFFER_TOO_SMALL;
    *out = x;
    return MT_OK;
}

mt_err mt_xchg_send(mt_xchg *m, mt_xchg_xchg *xc, uint8_t opcode, mt_span payload, bool reliable)
{
    mt_xchg_session *s = xc->session;
    bool rel = reliable && xc_mrp(s);
    bool ack = xc->ack_pending;
    mt_proto_hdr ph;
    uint32_t ctr, now;
    size_t len;
    int b;
    mt_err e;
    if (!xc->used || xc->closing || (rel && xc_awaiting(xc))) return MT_ERR_STATE;
    b = txbuf_get(m);
    if (b < 0) return MT_ERR_BUFFER_TOO_SMALL;
    memset(&ph, 0, sizeof ph);
    ph.flags = (uint8_t)((xc->initiator ? MT_XCHG_INITIATOR : 0) | (rel ? MT_XCHG_RELIABLE : 0) | (ack ? MT_XCHG_ACK : 0));
    ph.opcode = opcode;
    ph.exchange_id = xc->id;
    ph.protocol_id = xc->proto->protocol_id;
    ph.ack_counter = xc->ack_counter;
    e = build(m, s, m->txbuf[b], MT_XCHG_MAX_FRAME, &ph, payload, &len, &ctr);
    if (e != MT_OK) { txbuf_put(m, b); return e; }
    emit(m, s, m->txbuf[b], len);
    now = xc->last_activity = xc_now(m);
    if (ack) xc->ack_pending = false; /* piggybacked */
    if (!rel) { txbuf_put(m, b); return MT_OK; }
    xc->txbuf = (int8_t)b;
    xc->tx_len = (uint16_t)len;
    xc->tx_counter = ctr;
    xc->retrans = 0;
    xc->retx_due = now + retx_wait(m, s, 0, now);
    return MT_OK;
}

/* Send the ack we owe the peer now instead of piggybacking it. */
static void flush_ack(mt_xchg *m, mt_xchg_xchg *xc)
{
    xc_send_ack(m, xc->session, xc->id, xc->initiator, xc->ack_counter);
    xc->ack_pending = false;
}

void mt_xchg_close(mt_xchg *m, mt_xchg_xchg *xc)
{
    if (!xc->used || xc->closing) return;
    if (xc->ack_pending) flush_ack(m, xc);
    if (xc_awaiting(xc)) { xc->closing = true; return; }
    xc_free(m, xc, (mt_xchg_end)0);
}

void xc_on_ack(mt_xchg *m, mt_xchg_xchg *xc, uint32_t ack_counter)
{
    if (!xc_awaiting(xc) || ack_counter != xc->tx_counter) return;
    txbuf_put(m, xc->txbuf);
    xc->txbuf = -1;
    if (xc->closing) xc_free(m, xc, (mt_xchg_end)0);
}

/* ---- timers ---- */
uint32_t mt_xchg_poll(mt_xchg *m)
{
    uint32_t now = xc_now(m), next = UINT32_MAX;
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++) {
        mt_xchg_xchg *x = &m->xc[i];
        if (!x->used) continue;
        if (x->ack_pending && mt_due(now, x->ack_due)) flush_ack(m, x);
        if (xc_awaiting(x) && mt_due(now, x->retx_due)) {
            if (x->retrans >= MT_XCHG_MAX_RETRANS) { xc_free(m, x, MT_XCHG_END_MRP); continue; }
            x->retrans++;
            emit(m, x->session, m->txbuf[x->txbuf], x->tx_len);
            x->retx_due = now + retx_wait(m, x->session, x->retrans, now);
        } else if (!xc_awaiting(x) && now - x->last_activity >= MT_XCHG_XCHG_IDLE_MS) {
            xc_free(m, x, MT_XCHG_END_IDLE);
            continue;
        }
        if (x->ack_pending) next = mt_min_u32(next, mt_until(now, x->ack_due));
        if (xc_awaiting(x)) next = mt_min_u32(next, mt_until(now, x->retx_due));
        else next = mt_min_u32(next, mt_until(now, x->last_activity + MT_XCHG_XCHG_IDLE_MS));
    }
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++) {
        mt_xchg_session *s = &m->sess[i];
        if (s->kind != MT_SESS_UNSECURED || xs_has_xchg(m, s)) continue;
        if (now - s->last_activity >= MT_XCHG_UNSEC_IDLE_MS) { mt_xchg_session_close(m, s, MT_XCHG_END_IDLE); continue; }
        next = mt_min_u32(next, mt_until(now, s->last_activity + MT_XCHG_UNSEC_IDLE_MS));
    }
    return next;
}
