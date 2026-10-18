/* Host tests for matter-xchg. A fake clock and a scripted peer drive the layer; frames the device sends are
 * recorded and decoded again (secure ones with the session keys). Timing follows spec 4.12.2.1:
 * wait = base * 1.1 * 1.6^max(0,n-1) * (1 + rnd/256 * 0.25), base = peer active interval (300 ms default)
 * if the peer was heard in the last 4 s, else its idle interval (500 ms); 4 retransmissions; standalone ack
 * after 200 ms. Integer steps are spelled out in the expected numbers below. */
#include <stdio.h>
#include <string.h>

#include "mt_xchg.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)
#define AWAITING(xc) ((xc)->txbuf >= 0) /* our reliable message is waiting for its ack */

/* ---- fake world ---- */
static mt_xchg M;
static uint32_t now;
static uint8_t jitter;      /* what the 1-byte random request (MRP jitter) returns */
static uint32_t rng_state;

typedef struct { uint8_t t; uint8_t f[256]; size_t n; uint32_t at; mt_xchg_addr to; } sent_t;
static sent_t sent[64];
static int nsent;

static uint32_t p_now(void *c) { (void)c; return now; }
static void p_send(void *c, mt_xchg_transport t, const mt_xchg_addr *to, mt_span f)
{
    (void)c;
    if (nsent < 64 && f.len <= sizeof sent[0].f) {
        sent[nsent].t = (uint8_t)t;
        memcpy(sent[nsent].f, f.p, f.len);
        sent[nsent].n = f.len;
        sent[nsent].at = now;
        sent[nsent].to = *to;
    }
    nsent++;
}
static void p_random(void *c, uint8_t *out, size_t len)
{
    (void)c;
    if (len == 1) { out[0] = jitter; return; }
    for (size_t i = 0; i < len; i++) { rng_state = rng_state * 1664525u + 1013904223u; out[i] = (uint8_t)(rng_state >> 24); }
}

/* ---- scripted protocol handler ---- */
typedef struct {
    mt_xchg_proto p;
    int calls, closes;
    mt_xchg_end why;
    mt_proto_hdr ph;
    uint8_t pl[64];
    size_t pl_len;
    mt_xchg_xchg *xc;
    int reply_op;       /* -1: stay silent */
    bool reply_rel, close_after;
    bool close_session;  /* on_close closes the exchange's session (re-entry) */
} H;
static H h0, h1;

static void h_msg(void *ctx, mt_xchg_xchg *xc, const mt_proto_hdr *ph, mt_span pl)
{
    H *h = ctx;
    h->calls++;
    h->ph = *ph;
    h->xc = xc;
    h->pl_len = pl.len < sizeof h->pl ? pl.len : sizeof h->pl;
    memcpy(h->pl, pl.p, h->pl_len);
    if (h->reply_op >= 0) CHECK(mt_xchg_send(&M, xc, (uint8_t)h->reply_op, mt_span_of("ok", 2), h->reply_rel) == MT_OK);
    if (h->close_after) mt_xchg_close(&M, xc);
}
static void h_close(void *ctx, mt_xchg_xchg *xc, mt_xchg_end why)
{
    H *h = ctx;
    h->closes++;
    h->why = why;
    if (h->close_session) mt_xchg_session_close(&M, xc->session, why);
}

static int cb_calls;
static uint16_t cb_id;
static mt_xchg_end cb_why;
static void sess_cb(void *c, const mt_xchg_session *s, mt_xchg_end why) { (void)c; cb_calls++; cb_id = s->local_id; cb_why = why; }

static void reset(void)
{
    mt_xchg_ports p = { NULL, p_now, p_send, p_random };
    memset(&h0, 0, sizeof h0);
    memset(&h1, 0, sizeof h1);
    h0.p = (mt_xchg_proto){ 0x0000, &h0, h_msg, h_close };
    h1.p = (mt_xchg_proto){ 0x0001, &h1, h_msg, h_close };
    h0.reply_op = h1.reply_op = -1;
    now = 1000;
    jitter = 0;
    rng_state = 12345;
    nsent = 0;
    cb_calls = 0;
    mt_xchg_init(&M, &p);
    mt_xchg_set_session_cb(&M, sess_cb, NULL);
    CHECK(mt_xchg_register(&M, &h0.p) == MT_OK);
    CHECK(mt_xchg_register(&M, &h1.p) == MT_OK);
}

static int n_xchg(void)
{
    int n = 0;
    for (int i = 0; i < MT_XCHG_N_EXCHANGES; i++) n += M.xc[i].used;
    return n;
}

/* ---- scripted peer ---- */
#define PEER 0x1122334455667788ull
static const uint8_t K_ENC[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
static const uint8_t K_DEC[16] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f };

typedef struct { uint8_t flags, op; uint16_t xid, proto; uint32_t ack; const char *pl; } pm; /* peer message body */

static size_t body(uint8_t *b, size_t at, const pm *m)
{
    mt_proto_hdr ph = { m->flags, m->op, m->xid, 0, m->proto, m->ack };
    size_t n, pl = m->pl ? strlen(m->pl) : 0;
    CHECK(mt_proto_hdr_encode(&ph, mt_buf_of(b + at, 32), &n) == MT_OK);
    memcpy(b + at + n, m->pl, pl);
    return n + pl;
}

static size_t mk_unsec(uint8_t *b, uint64_t src, uint32_t ctr, const pm *m)
{
    mt_msg_hdr h = { 0 };
    size_t hl;
    h.has_src = true;
    h.src = src;
    h.counter = ctr;
    CHECK(mt_msg_hdr_encode(&h, mt_buf_of(b, 32), &hl) == MT_OK);
    return hl + body(b, hl, m);
}

static uint64_t peer_nonce; /* the peer's node ID in its frames' nonce: set by add_session (0 for PASE) */
static size_t mk_sec(uint8_t *b, uint16_t dev_session, uint32_t ctr, const pm *m)
{
    mt_msg_hdr h = { 0 };
    size_t hl, pl, out;
    h.session_id = dev_session;
    h.counter = ctr;
    CHECK(mt_msg_hdr_encode(&h, mt_buf_of(b, 32), &hl) == MT_OK);
    pl = body(b, hl, m);
    CHECK(mt_msg_seal(K_DEC, peer_nonce, &h, mt_buf_of(b, 256), hl, pl, &out) == MT_OK);
    return out;
}

static void rx_unsec(uint32_t ctr, pm m)
{
    uint8_t b[256];
    size_t n = mk_unsec(b, PEER, ctr, &m);
    mt_xchg_on_rx(&M, MT_XCHG_UDP, &(mt_xchg_addr){ .port = 5540 }, b, n);
}
static void rx_sec(uint16_t dev_session, uint32_t ctr, pm m)
{
    uint8_t b[256];
    size_t n = mk_sec(b, dev_session, ctr, &m);
    mt_xchg_on_rx(&M, MT_XCHG_UDP, &(mt_xchg_addr){ .port = 5540 }, b, n);
}

/* Decodes recorded frame i. secure: opened with K_ENC (nonce source 0 = PASE). */
static uint64_t nonce_node; /* source node of the device's frames: set by add_session (0 for PASE) */
typedef struct { mt_msg_hdr h; mt_proto_hdr ph; uint8_t pl[64]; size_t pl_len; } dec_t;
static void parse(int i, bool secure, dec_t *d)
{
    uint8_t b[256];
    size_t off, len, pl;
    memcpy(b, sent[i].f, sent[i].n);
    if (secure) CHECK(mt_msg_open(K_ENC, nonce_node, b, sent[i].n, &d->h, &off, &len) == MT_OK);
    else { CHECK(mt_msg_hdr_decode(mt_span_of(b, sent[i].n), &d->h, &off) == MT_OK); len = sent[i].n - off; }
    CHECK(mt_proto_hdr_decode(mt_span_of(b + off, len), &d->ph, &pl) == MT_OK);
    d->pl_len = len - pl;
    memcpy(d->pl, b + off + pl, d->pl_len);
}

static mt_xchg_session *add_session(mt_sess_kind k, uint16_t id, mt_xchg_transport t)
{
    mt_xchg_session_params p;
    mt_xchg_session *s = NULL;
    memset(&p, 0, sizeof p);
    p.kind = k;
    p.transport = t;
    p.local_id = id;
    p.peer_id = 0x4321;
    p.peer_node = k == MT_SESS_CASE ? PEER : 0;
    p.local_node = k == MT_SESS_CASE ? 0xAAAA : 0;
    nonce_node = p.local_node;
    peer_nonce = p.peer_node;
    memcpy(p.enc_key, K_ENC, 16);
    memcpy(p.dec_key, K_DEC, 16);
    CHECK(mt_xchg_session_add(&M, &p, &s) == MT_OK);
    return s;
}

#define IR (MT_XCHG_INITIATOR | MT_XCHG_RELIABLE)

/* ---- tests ---- */
static void test_backoff_formula(void)
{
    CHECK(mt_xchg_backoff_ms(300, 0, 0) == 330);
    CHECK(mt_xchg_backoff_ms(300, 1, 0) == 330);  /* threshold 1: no growth yet */
    CHECK(mt_xchg_backoff_ms(300, 2, 0) == 528);
    CHECK(mt_xchg_backoff_ms(300, 3, 0) == 844);
    CHECK(mt_xchg_backoff_ms(300, 4, 0) == 1350);
    CHECK(mt_xchg_backoff_ms(300, 0, 255) == 330 + 82); /* jitter < +25 % */
    CHECK(mt_xchg_backoff_ms(500, 0, 0) == 550);
    CHECK(mt_xchg_backoff_ms(500, 2, 0) == 880);
    CHECK(mt_xchg_backoff_ms(3600000, 4, 255) > 3600000u && mt_xchg_backoff_ms(3600000, 4, 255) < 0xFFFFFFFFu);
    CHECK(mt_xchg_backoff_ms(3904515726u, 0, 0) == 0xFFFFFFFFu);   /* saturates instead of wrapping to 2 ms */
    /* peer-announced intervals are clamped to the spec maximum; 0 keeps the current value */
    mt_xchg_session s = { .idle_ms = 500, .active_ms = 300 };
    mt_xchg_session_set_mrp(&s, 3904515726u, 0);
    CHECK(s.idle_ms == MT_XCHG_MRP_MAX_MS && s.active_ms == 300);
    mt_xchg_session_set_mrp(&s, 1000, UINT32_MAX);
    CHECK(s.idle_ms == 1000 && s.active_ms == MT_XCHG_MRP_MAX_MS);
}

static void test_unsecured_piggyback(void)
{
    dec_t d;
    reset();
    h0.reply_op = 0x21;
    h0.reply_rel = true;
    rx_unsec(100, (pm){ IR, 0x20, 0x77, 0, 0, "hi" });
    CHECK(h0.calls == 1 && h0.ph.opcode == 0x20 && h0.pl_len == 2 && !memcmp(h0.pl, "hi", 2));
    CHECK(nsent == 1);
    parse(0, false, &d);
    CHECK(d.h.session_id == 0 && d.h.dsiz == MT_MSG_DSIZ_NODE && d.h.dst == PEER && !d.h.has_src);
    CHECK(d.ph.flags == (MT_XCHG_ACK | MT_XCHG_RELIABLE)); /* responder: no I; ack piggybacked */
    CHECK(d.ph.ack_counter == 100 && d.ph.exchange_id == 0x77 && d.ph.opcode == 0x21 && d.pl_len == 2);
    /* the peer acks with a standalone ack; no retransmit and no extra ack ever follows */
    rx_unsec(101, (pm){ MT_XCHG_INITIATOR | MT_XCHG_ACK, MT_XCHG_OP_STANDALONE_ACK, 0x77, 0, d.h.counter, NULL });
    CHECK(h0.calls == 1);
    now += 5000;
    mt_xchg_poll(&M);
    CHECK(nsent == 1 && h0.closes == 0);
}

static void test_standalone_ack_timer(void)
{
    dec_t d;
    reset();
    rx_unsec(100, (pm){ IR, 0x20, 0x77, 0, 0, "x" });
    CHECK(h0.calls == 1 && nsent == 0);
    CHECK(mt_xchg_poll(&M) == 200);
    now += 199;
    CHECK(mt_xchg_poll(&M) == 1 && nsent == 0);
    now += 1;
    mt_xchg_poll(&M);
    CHECK(nsent == 1);
    parse(0, false, &d);
    CHECK(d.ph.flags == MT_XCHG_ACK && d.ph.opcode == MT_XCHG_OP_STANDALONE_ACK && d.ph.protocol_id == 0);
    CHECK(d.ph.ack_counter == 100 && d.ph.exchange_id == 0x77 && d.pl_len == 0);
    now += 1000;
    mt_xchg_poll(&M);
    CHECK(nsent == 1); /* acked once only */
}

static void test_duplicates(void)
{
    dec_t d;
    reset();
    rx_unsec(100, (pm){ IR, 0x20, 0x77, 0, 0, "x" });
    rx_unsec(100, (pm){ IR, 0x20, 0x77, 0, 0, "x" }); /* retransmission of the same message */
    CHECK(h0.calls == 1);
    CHECK(nsent == 1); /* duplicate of a reliable message is acked at once */
    parse(0, false, &d);
    CHECK(d.ph.flags == MT_XCHG_ACK && d.ph.ack_counter == 100 && d.ph.exchange_id == 0x77);
    rx_unsec(105, (pm){ MT_XCHG_INITIATOR, 0x20, 0x78, 0, 0, "y" });
    CHECK(h0.calls == 2);
    rx_unsec(105, (pm){ MT_XCHG_INITIATOR, 0x20, 0x78, 0, 0, "y" }); /* unreliable duplicate: silent */
    CHECK(h0.calls == 2 && nsent == 1);
    /* a duplicate for an exchange that no longer exists is still acked */
    mt_xchg_close(&M, h0.xc);
    CHECK(nsent == 1);
    rx_unsec(100, (pm){ IR, 0x20, 0x77, 0, 0, "x" });
    CHECK(nsent == 2 && h0.calls == 2);
}

static void test_retransmit_schedule(void)
{
    static const uint32_t at[] = { 330, 660, 1188, 2032 }; /* 330, 330, 528, 844 after each send */
    dec_t d, d1;
    reset();
    h0.reply_op = 0x21;
    h0.reply_rel = true;
    rx_unsec(100, (pm){ MT_XCHG_INITIATOR, 0x20, 0x77, 0, 0, "q" });
    CHECK(nsent == 1);
    uint32_t t0 = now;
    for (int i = 0; i < 4; i++) {
        now = t0 + at[i] - 1;
        mt_xchg_poll(&M);
        CHECK(nsent == i + 1);
        now = t0 + at[i];
        mt_xchg_poll(&M);
        CHECK(nsent == i + 2 && sent[i + 1].at == t0 + at[i]);
        CHECK(sent[i + 1].n == sent[0].n && !memcmp(sent[i + 1].f, sent[0].f, sent[0].n)); /* identical bytes */
    }
    now = t0 + 3382 - 1; /* last wait 1350 */
    mt_xchg_poll(&M);
    CHECK(h0.closes == 0 && nsent == 5);
    now = t0 + 3382;
    mt_xchg_poll(&M);
    CHECK(nsent == 5 && h0.closes == 1 && h0.why == MT_XCHG_END_MRP && n_xchg() == 0);
    parse(0, false, &d);
    parse(4, false, &d1);
    CHECK(d.h.counter == d1.h.counter); /* retransmissions keep the message counter */

    /* the wait follows the peer's idle interval when it was last heard more than 4 s ago */
    reset();
    mt_xchg_session *s = add_session(MT_SESS_CASE, 0x1234, MT_XCHG_UDP);
    mt_xchg_xchg *xc;
    now += 5000;
    CHECK(mt_xchg_open(&M, s, 1, &xc) == MT_OK);
    CHECK(mt_xchg_send(&M, xc, 5, mt_span_of("a", 1), true) == MT_OK);
    now += 549;
    mt_xchg_poll(&M);
    CHECK(nsent == 1);
    now += 1;
    mt_xchg_poll(&M);
    CHECK(nsent == 2);
    /* jitter adds up to a quarter */
    reset();
    jitter = 255;
    h0.reply_op = 0x21;
    h0.reply_rel = true;
    rx_unsec(100, (pm){ MT_XCHG_INITIATOR, 0x20, 0x77, 0, 0, "q" });
    now += 411;
    mt_xchg_poll(&M);
    CHECK(nsent == 1);
    now += 1;
    mt_xchg_poll(&M);
    CHECK(nsent == 2);
}

static void test_secure_session(void)
{
    uint8_t b[256];
    dec_t d;
    mt_xchg_session *s;
    size_t n;
    reset();
    s = add_session(MT_SESS_PASE, 0x1234, MT_XCHG_UDP);
    h1.reply_op = 0x31;
    h1.reply_rel = false;
    rx_sec(0x1234, 500, (pm){ IR, 0x30, 9, 1, 0, "get" });
    CHECK(h1.calls == 1 && h1.pl_len == 3 && !memcmp(h1.pl, "get", 3));
    CHECK(nsent == 1);
    parse(0, true, &d);
    CHECK(d.h.session_id == 0x4321 && d.h.dsiz == MT_MSG_DSIZ_NONE && d.ph.flags == MT_XCHG_ACK);
    CHECK(d.ph.ack_counter == 500 && d.ph.protocol_id == 1 && d.ph.opcode == 0x31 && d.pl_len == 2);
    /* counters increase per frame */
    rx_sec(0x1234, 501, (pm){ IR, 0x30, 10, 1, 0, "get" });
    parse(1, true, &d);
    CHECK(d.h.counter == s->tx.next - 1);
    /* wrong session id, bad MIC, replay, stale */
    rx_sec(0x1235, 502, (pm){ IR, 0x30, 11, 1, 0, "z" });
    n = mk_sec(b, 0x1234, 503, &(pm){ IR, 0x30, 12, 1, 0, "z" });
    b[n - 1] ^= 1;
    mt_xchg_on_rx(&M, MT_XCHG_UDP, &(mt_xchg_addr){ 0 }, b, n);
    CHECK(h1.calls == 2 && nsent == 2);
    rx_sec(0x1234, 501, (pm){ IR, 0x30, 10, 1, 0, "get" }); /* replay of a reliable message: acked, not delivered */
    CHECK(h1.calls == 2 && nsent == 3);
    rx_sec(0x1234, 9000, (pm){ IR, 0x30, 13, 1, 0, "n" });
    CHECK(h1.calls == 3 && nsent == 4);
    rx_sec(0x1234, 100, (pm){ IR, 0x30, 14, 1, 0, "old" }); /* beyond the window: dropped without an ack */
    CHECK(h1.calls == 3 && nsent == 4);
    /* the peer address follows authenticated messages */
    CHECK(s->addr.port == 5540 && sent[0].to.port == 5540);
}

static void test_btp_no_mrp(void)
{
    uint8_t b[256];
    size_t n;
    dec_t d;
    reset();
    add_session(MT_SESS_CASE, 0x1234, MT_XCHG_BTP);
    h1.reply_op = 0x31;
    h1.reply_rel = true; /* asked for, but BTP is reliable itself */
    n = mk_sec(b, 0x1234, 7, &(pm){ IR, 0x30, 9, 1, 0, "get" });
    mt_xchg_on_rx(&M, MT_XCHG_BTP, NULL, b, n);
    CHECK(h1.calls == 1 && nsent == 1 && sent[0].t == MT_XCHG_BTP);
    parse(0, true, &d); /* CASE nonce uses our node ID */
    CHECK(d.h.session_id == 0x4321 && d.ph.flags == 0); /* no R, no ack on BTP */
    now += 10000;
    mt_xchg_poll(&M);
    CHECK(nsent == 1 && h1.closes == 0);
    /* same session id over UDP is not this session */
    rx_sec(0x1234, 8, (pm){ IR, 0x30, 9, 1, 0, "get" });
    CHECK(h1.calls == 1);
}

static void test_eviction(void)
{
    mt_xchg_session *s[10];
    mt_xchg_xchg *xc;
    mt_xchg_session_params p;
    reset();
    for (int i = 1; i <= 8; i++) { now += 100; s[i] = add_session(MT_SESS_CASE, (uint16_t)i, MT_XCHG_UDP); }
    mt_xchg_session_set_subs(s[1], 1);
    CHECK(mt_xchg_open(&M, s[2], 1, &xc) == MT_OK);
    now += 100;
    add_session(MT_SESS_CASE, 9, MT_XCHG_UDP);
    CHECK(cb_calls == 1 && cb_id == 3 && cb_why == MT_XCHG_END_EVICTED); /* oldest without subs/exchanges */
    CHECK(!mt_xchg_session_find(&M, 3) && mt_xchg_session_find(&M, 9) && mt_xchg_session_find(&M, 1));
    CHECK(h1.closes == 0 && n_xchg() == 1);
    now += 100;
    add_session(MT_SESS_CASE, 10, MT_XCHG_UDP);
    CHECK(cb_id == 4);
    /* everyone busy: least recently active goes, its exchange is reported */
    for (int i = 5; i <= 9; i++) mt_xchg_session_set_subs(mt_xchg_session_find(&M, (uint16_t)i), 1);
    mt_xchg_session_set_subs(mt_xchg_session_find(&M, 10), 1);
    mt_xchg_session_set_subs(mt_xchg_session_find(&M, 2), 1);
    now += 100;
    add_session(MT_SESS_CASE, 11, MT_XCHG_UDP);
    mt_xchg_session_set_subs(mt_xchg_session_find(&M, 11), 1);
    CHECK(cb_id == 1 && cb_why == MT_XCHG_END_EVICTED);
    now += 100;
    add_session(MT_SESS_CASE, 12, MT_XCHG_UDP);
    CHECK(cb_id == 2 && h1.closes == 1 && h1.why == MT_XCHG_END_EVICTED && n_xchg() == 0);
    /* duplicate local id */
    memset(&p, 0, sizeof p);
    p.kind = MT_SESS_CASE;
    p.local_id = 12;
    CHECK(mt_xchg_session_add(&M, &p, &s[0]) == MT_ERR_INVALID);
    p.local_id = 0;
    CHECK(mt_xchg_session_add(&M, &p, &s[0]) == MT_ERR_INVALID);

    /* PASE is protected during the commissioning window */
    reset();
    mt_xchg_set_commissioning(&M, true);
    for (int i = 1; i <= 8; i++) { now += 10; add_session(MT_SESS_PASE, (uint16_t)i, MT_XCHG_UDP); }
    memset(&p, 0, sizeof p);
    p.kind = MT_SESS_CASE;
    p.local_id = 99;
    CHECK(mt_xchg_session_add(&M, &p, &s[0]) == MT_ERR_BUFFER_TOO_SMALL && cb_calls == 0);
    mt_xchg_set_commissioning(&M, false);
    CHECK(mt_xchg_session_add(&M, &p, &s[0]) == MT_OK && cb_id == 1);

    /* a stale PASE (window closed) goes before any CASE, even a less recently used one */
    reset();
    for (int i = 1; i <= 4; i++) { now += 10; add_session(MT_SESS_CASE, (uint16_t)i, MT_XCHG_UDP); }
    for (int i = 5; i <= 8; i++) { now += 10; add_session(MT_SESS_PASE, (uint16_t)i, MT_XCHG_UDP); }
    now += 10;
    add_session(MT_SESS_CASE, 20, MT_XCHG_UDP);
    CHECK(cb_id == 5);

    /* a spoofable unsecured message never displaces a CASE session, but may take a stale PASE */
    reset();
    for (int i = 1; i <= 8; i++) { now += 10; add_session(MT_SESS_CASE, (uint16_t)i, MT_XCHG_UDP); }
    rx_unsec(1, (pm){ IR, 0x20, 1, 0, 0, "x" });
    CHECK(h0.calls == 0 && cb_calls == 0 && nsent == 0);
    reset();
    for (int i = 1; i <= 7; i++) { now += 10; add_session(MT_SESS_CASE, (uint16_t)i, MT_XCHG_UDP); }
    add_session(MT_SESS_PASE, 8, MT_XCHG_UDP);
    rx_unsec(1, (pm){ IR, 0x20, 1, 0, 0, "x" });
    CHECK(h0.calls == 1 && cb_calls == 1 && cb_id == 8);
}

static void test_table_full_exchanges(void)
{
    uint8_t b[256];
    size_t n;
    reset();
    for (int i = 0; i < MT_XCHG_N_EXCHANGES; i++) {
        pm m = { IR, 0x20, (uint16_t)(0x100 + i), 0, 0, "x" };
        n = mk_unsec(b, PEER + (uint64_t)i, 50, &m);
        mt_xchg_on_rx(&M, MT_XCHG_UDP, &(mt_xchg_addr){ 0 }, b, n);
    }
    CHECK(h0.calls == MT_XCHG_N_EXCHANGES && n_xchg() == MT_XCHG_N_EXCHANGES);
    /* no slot: dropped unrecorded, so the peer's retransmission is taken as new once there is room */
    n = mk_unsec(b, PEER + 100, 50, &(pm){ IR, 0x20, 0x300, 0, 0, "late" });
    mt_xchg_on_rx(&M, MT_XCHG_UDP, &(mt_xchg_addr){ 0 }, b, n);
    CHECK(h0.calls == MT_XCHG_N_EXCHANGES && nsent == 0);
    mt_xchg_close(&M, h0.xc);
    CHECK(nsent == 1); /* close flushed that exchange's ack */
    mt_xchg_on_rx(&M, MT_XCHG_UDP, &(mt_xchg_addr){ 0 }, b, n);
    CHECK(h0.calls == MT_XCHG_N_EXCHANGES + 1 && !memcmp(h0.pl, "late", 4));
}

static void test_initiated_exchange(void)
{
    mt_xchg_session *s;
    mt_xchg_xchg *xc;
    dec_t d;
    reset();
    s = add_session(MT_SESS_CASE, 0x1234, MT_XCHG_UDP);
    CHECK(mt_xchg_open(&M, s, 0x77, &xc) == MT_ERR_NOT_FOUND);
    CHECK(mt_xchg_open(&M, s, 1, &xc) == MT_OK && xc->initiator);
    CHECK(mt_xchg_send(&M, xc, 5, mt_span_of("rep", 3), true) == MT_OK);
    CHECK(mt_xchg_send(&M, xc, 5, mt_span_of("rep", 3), true) == MT_ERR_STATE); /* one reliable message at a time */
    parse(0, true, &d);
    CHECK(d.ph.flags == IR && d.ph.exchange_id == xc->id && d.ph.protocol_id == 1);
    /* the peer reuses the same exchange ID as *its* initiator: a different exchange */
    rx_sec(0x1234, 10, (pm){ MT_XCHG_INITIATOR, 0x30, xc->id, 1, 0, "own" });
    CHECK(h1.calls == 1 && h1.xc != xc && !h1.xc->initiator);
    CHECK(AWAITING(xc));
    /* the response (no I flag) carries the ack */
    rx_sec(0x1234, 11, (pm){ MT_XCHG_ACK, 0x06, xc->id, 1, d.h.counter, "resp" });
    CHECK(h1.calls == 2 && h1.xc == xc && !AWAITING(xc));
    now += 10000;
    mt_xchg_poll(&M);
    CHECK(nsent == 1); /* nothing retransmitted */
    /* an ack for another counter does not release it */
    CHECK(mt_xchg_send(&M, xc, 5, mt_span_of("b", 1), true) == MT_OK);
    rx_sec(0x1234, 12, (pm){ MT_XCHG_ACK, 0x06, xc->id, 1, 0xDEAD, "r" });
    CHECK(AWAITING(xc));
}

/* A lost standalone ack: the peer's next message on the exchange (no ack flag) counts as the ack, so a reply
 * can follow at once; a message with a wrong ack counter, a standalone ack and another exchange do not. */
static void test_implicit_ack(void)
{
    mt_xchg_session *s;
    mt_xchg_xchg *xc;
    int before;
    reset();
    s = add_session(MT_SESS_CASE, 0x1234, MT_XCHG_UDP);
    CHECK(mt_xchg_open(&M, s, 1, &xc) == MT_OK);
    CHECK(mt_xchg_send(&M, xc, 5, mt_span_of("a", 1), true) == MT_OK);
    rx_sec(0x1234, 20, (pm){ MT_XCHG_ACK, 0x06, xc->id, 1, 0xDEAD, "x" });  /* wrong ack: no proof */
    CHECK(AWAITING(xc));
    rx_sec(0x1234, 21, (pm){ MT_XCHG_INITIATOR, 0x06, xc->id + 1, 1, 0, "y" }); /* other exchange */
    CHECK(AWAITING(xc));
    rx_sec(0x1234, 22, (pm){ MT_XCHG_RELIABLE, 0x06, xc->id, 1, 0, "z" });  /* reply, ack lost */
    CHECK(!AWAITING(xc) && xc->txbuf == -1 && xc->ack_pending);
    CHECK(mt_xchg_send(&M, xc, 5, mt_span_of("b", 1), true) == MT_OK);
    CHECK(AWAITING(xc));
    before = nsent;
    now += 10000;
    mt_xchg_poll(&M);                    /* only the new message is retransmitted, never the old one */
    CHECK(nsent > before);
    /* a duplicate of the reply must not release the new message */
    rx_sec(0x1234, 22, (pm){ MT_XCHG_RELIABLE, 0x06, xc->id, 1, 0, "z" });
    CHECK(AWAITING(xc));
}

static void test_unknown_and_spurious(void)
{
    dec_t d;
    reset();
    add_session(MT_SESS_PASE, 0x1234, MT_XCHG_UDP);
    rx_sec(0x1234, 1, (pm){ IR, 0x20, 5, 0x00AA, 0, "x" }); /* no handler: ack so the peer stops, nothing to deliver */
    CHECK(h0.calls == 0 && h1.calls == 0 && n_xchg() == 0 && nsent == 1);
    parse(0, true, &d);
    CHECK(d.ph.flags == MT_XCHG_ACK && d.ph.ack_counter == 1);
    rx_sec(0x1234, 2, (pm){ MT_XCHG_INITIATOR, 0x20, 5, 0x00AA, 0, "x" });
    rx_sec(0x1234, 3, (pm){ MT_XCHG_ACK, 0x20, 6, 0, 1234, NULL }); /* ack for nothing */
    rx_sec(0x1234, 4, (pm){ MT_XCHG_ACK | MT_XCHG_INITIATOR, MT_XCHG_OP_STANDALONE_ACK, 6, 0, 1234, NULL });
    CHECK(nsent == 1 && n_xchg() == 0);
    rx_unsec(5, (pm){ IR, 0x20, 5, 0, 0, "x" }); /* vendor-specific frames are not ours */
}

static int n_sess(mt_sess_kind k)
{
    int n = 0;
    for (int i = 0; i < MT_XCHG_N_SESSIONS; i++) n += M.sess[i].kind == k;
    return n;
}

/* Unsecured sessions carry session establishment only (Secure Channel). Anything else on session 0, e.g. an
 * IM request, is dropped before a session or exchange exists, and nothing is acked. A new unsecured session
 * is created only for a peer-initiated Secure Channel message that is not a standalone ack. */
static void test_unsecured_secure_channel_only(void)
{
    reset();
    rx_unsec(1, (pm){ IR, 0x02, 9, 0x0001, 0, "read" });                      /* IM ReadRequest, plaintext */
    CHECK(h1.calls == 0 && n_xchg() == 0 && nsent == 0 && n_sess(MT_SESS_UNSECURED) == 0);
    rx_unsec(2, (pm){ IR, 0x20, 9, 0x00AA, 0, "x" });                         /* unknown protocol */
    CHECK(nsent == 0 && n_sess(MT_SESS_UNSECURED) == 0);
    rx_unsec(3, (pm){ MT_XCHG_ACK | MT_XCHG_INITIATOR, MT_XCHG_OP_STANDALONE_ACK, 9, 0, 77, NULL }); /* spoofed ack */
    CHECK(nsent == 0 && n_sess(MT_SESS_UNSECURED) == 0);
    rx_unsec(4, (pm){ MT_XCHG_RELIABLE, 0x21, 9, 0, 0, "resp" });             /* responder-role frame */
    CHECK(nsent == 0 && n_sess(MT_SESS_UNSECURED) == 0);
    rx_unsec(5, (pm){ IR, 0x20, 9, 0, 0, "pbkdf" });                          /* session establishment: accepted */
    CHECK(h0.calls == 1 && n_sess(MT_SESS_UNSECURED) == 1);
    /* An established unsecured session still does not carry IM. */
    rx_unsec(6, (pm){ IR, 0x02, 10, 0x0001, 0, "read" });
    CHECK(h1.calls == 0 && n_xchg() == 1);
}

static void test_close_semantics(void)
{
    dec_t d;
    mt_xchg_xchg *xc;
    reset();
    h0.close_after = true;
    rx_unsec(100, (pm){ IR, 0x20, 0x77, 0, 0, "x" }); /* close without replying: ack flushed, slot freed */
    CHECK(nsent == 1 && n_xchg() == 0 && h0.closes == 0);
    parse(0, false, &d);
    CHECK(d.ph.flags == MT_XCHG_ACK && d.ph.ack_counter == 100);

    /* close with a reliable message in flight: held until acked, then released silently */
    reset();
    h0.reply_op = 0x21;
    h0.reply_rel = true;
    h0.close_after = true;
    rx_unsec(100, (pm){ IR, 0x20, 0x77, 0, 0, "x" });
    xc = h0.xc;
    CHECK(nsent == 1 && n_xchg() == 1 && xc->closing);
    parse(0, false, &d);
    rx_unsec(101, (pm){ MT_XCHG_INITIATOR | MT_XCHG_ACK, MT_XCHG_OP_STANDALONE_ACK, 0x77, 0, d.h.counter, NULL });
    CHECK(n_xchg() == 0 && h0.closes == 0);

    /* ... or until MRP gives up, which is reported */
    reset();
    h0.reply_op = 0x21;
    h0.reply_rel = true;
    h0.close_after = true;
    rx_unsec(100, (pm){ IR, 0x20, 0x77, 0, 0, "x" });
    for (int i = 0; i < 8; i++) { now += 3000; mt_xchg_poll(&M); } /* one step per due retransmission */
    CHECK(n_xchg() == 0 && h0.closes == 1 && h0.why == MT_XCHG_END_MRP && nsent == 5);

    /* a closing exchange delivers nothing more */
    reset();
    h0.reply_op = 0x21;
    h0.reply_rel = true;
    h0.close_after = true;
    rx_unsec(100, (pm){ IR, 0x20, 0x77, 0, 0, "x" });
    int before = nsent;
    rx_unsec(101, (pm){ IR, 0x22, 0x77, 0, 0, "late" });
    CHECK(h0.calls == 1 && nsent == before + 1);

    /* idle exchanges are dropped */
    reset();
    rx_unsec(100, (pm){ MT_XCHG_INITIATOR, 0x20, 0x77, 0, 0, "x" });
    now += MT_XCHG_XCHG_IDLE_MS - 1;
    mt_xchg_poll(&M);
    CHECK(n_xchg() == 1);
    now += 1;
    mt_xchg_poll(&M);
    CHECK(n_xchg() == 0 && h0.closes == 1 && h0.why == MT_XCHG_END_IDLE);
}

static void test_session_close_and_misc(void)
{
    mt_xchg_session *s;
    mt_xchg_xchg *x1, *x2;
    uint16_t id;
    uint8_t zero[16] = { 0 };
    reset();
    s = add_session(MT_SESS_CASE, 0x1234, MT_XCHG_UDP);
    CHECK(mt_xchg_open(&M, s, 0, &x1) == MT_OK && mt_xchg_open(&M, s, 1, &x2) == MT_OK && x1->id != x2->id);
    mt_xchg_send(&M, x1, 1, mt_span_of("a", 1), true);
    mt_xchg_session_close(&M, s, MT_XCHG_END_CLOSED);
    CHECK(h0.closes == 1 && h1.closes == 1 && h0.why == MT_XCHG_END_CLOSED && cb_calls == 1 && cb_id == 0x1234);
    CHECK(s->kind == MT_SESS_FREE && !memcmp(s->enc_key, zero, 16) && n_xchg() == 0);
    now += 10000;
    mt_xchg_poll(&M);
    CHECK(nsent == 1); /* no retransmit for a dead session */

    /* an on_close that closes its own session: every callback still runs once */
    s = add_session(MT_SESS_CASE, 0x2345, MT_XCHG_UDP);
    CHECK(mt_xchg_open(&M, s, 0, &x1) == MT_OK && mt_xchg_open(&M, s, 1, &x2) == MT_OK);
    h0.closes = h1.closes = cb_calls = 0;
    h0.close_session = true;
    mt_xchg_session_close(&M, s, MT_XCHG_END_CLOSED);
    CHECK(h0.closes == 1 && h1.closes == 1 && cb_calls == 1 && cb_id == 0x2345 && n_xchg() == 0);
    CHECK(s->kind == MT_SESS_FREE);
    h0.close_session = false;

    for (int i = 0; i < 50; i++) {
        CHECK(mt_xchg_session_id_alloc(&M, &id) == MT_OK && id != 0 && !mt_xchg_session_find(&M, id));
    }
    /* protocol table */
    CHECK(mt_xchg_register(&M, &h0.p) == MT_ERR_INVALID);
    mt_xchg_proto extra[3] = { { 2, NULL, h_msg, NULL }, { 3, NULL, h_msg, NULL }, { 4, NULL, h_msg, NULL } };
    CHECK(mt_xchg_register(&M, &extra[0]) == MT_OK && mt_xchg_register(&M, &extra[1]) == MT_OK);
    CHECK(mt_xchg_register(&M, &extra[2]) == MT_ERR_BUFFER_TOO_SMALL);
}

static void test_limits(void)
{
    mt_xchg_session *s;
    mt_xchg_xchg *xc;
    static uint8_t big[MT_XCHG_MAX_PAYLOAD + 1];
    reset();
    s = add_session(MT_SESS_CASE, 0x1234, MT_XCHG_UDP);
    CHECK(mt_xchg_open(&M, s, 1, &xc) == MT_OK);
    CHECK(mt_xchg_send(&M, xc, 1, mt_span_of(big, sizeof big), false) == MT_ERR_BUFFER_TOO_SMALL);
    s->tx.next = 0xFFFFFFFFu; /* last counter */
    CHECK(mt_xchg_send(&M, xc, 1, mt_span_of("a", 1), false) == MT_OK);
    CHECK(mt_xchg_send(&M, xc, 1, mt_span_of("a", 1), false) == MT_ERR_STATE);
    /* frame buffers: reliable sends hold one each */
    reset();
    s = add_session(MT_SESS_CASE, 0x1234, MT_XCHG_UDP);
    for (int i = 0; i < MT_XCHG_N_TXBUF; i++) {
        CHECK(mt_xchg_open(&M, s, 1, &xc) == MT_OK);
        CHECK(mt_xchg_send(&M, xc, 1, mt_span_of("a", 1), true) == MT_OK);
    }
    CHECK(mt_xchg_open(&M, s, 1, &xc) == MT_OK);
    CHECK(mt_xchg_send(&M, xc, 1, mt_span_of("a", 1), true) == MT_ERR_BUFFER_TOO_SMALL);
    CHECK(mt_xchg_send(&M, xc, 1, mt_span_of("a", 1), false) == MT_ERR_BUFFER_TOO_SMALL);
}

static void test_unsecured_reaping(void)
{
    reset();
    rx_unsec(100, (pm){ MT_XCHG_INITIATOR, 0x20, 0x77, 0, 0, "x" });
    mt_xchg_close(&M, h0.xc);
    CHECK(M.sess[0].kind == MT_SESS_UNSECURED && n_xchg() == 0);
    CHECK(mt_xchg_poll(&M) == MT_XCHG_UNSEC_IDLE_MS);
    now += MT_XCHG_UNSEC_IDLE_MS - 1;
    mt_xchg_poll(&M);
    CHECK(M.sess[0].kind == MT_SESS_UNSECURED && cb_calls == 0);
    now += 1;
    CHECK(mt_xchg_poll(&M) == UINT32_MAX);
    CHECK(M.sess[0].kind == MT_SESS_FREE && cb_calls == 1 && cb_why == MT_XCHG_END_IDLE);
}

int main(void)
{
    test_backoff_formula();
    test_unsecured_piggyback();
    test_standalone_ack_timer();
    test_duplicates();
    test_retransmit_schedule();
    test_secure_session();
    test_btp_no_mrp();
    test_eviction();
    test_table_full_exchanges();
    test_initiated_exchange();
    test_implicit_ack();
    test_unknown_and_spurious();
    test_unsecured_secure_channel_only();
    test_close_semantics();
    test_session_close_and_misc();
    test_limits();
    test_unsecured_reaping();
    printf("%d checks, %d failures\n", checks, failures);
    return failures != 0;
}
