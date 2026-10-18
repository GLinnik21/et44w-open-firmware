/* Host tests for matter-node, driven entirely in memory with a fake clock. The initiator is the shared
 * mt_test_init (the same code the POSIX loopback client uses). It shares the frame codecs, SPAKE2+ math and TLV
 * with the node, so passing shows the stack is self-consistent, not that chip-tool or Apple would accept it.
 * The one independent anchor: the PBKDF2 passcode derivation is checked against a chip-tool vector
 * (passcode 123456, as recorded in matter-pase's tests).
 *
 * World: one or two nodes, up to eight clients. Every datagram goes through the harness, which can drop the
 * next N frames in either direction. A client's recv() with an empty queue advances the fake clock by the wait
 * and polls the node, so the node's MRP retransmissions and timers run exactly as on a device. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mt_node.h"
#include "mt_test_init.h"
#include "attest.h"
#include "case_ini.h"

static int failures, checks, xfails;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)
/* A known open defect (listed in the review): reported, not counted as a failure. If it starts passing the
 * XPASS line says the entry can become a CHECK. */
#define XFAIL(c) do { checks++; if (!(c)) { xfails++; printf("XFAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } \
                      else printf("XPASS %s:%d  %s\n", __FILE__, __LINE__, #c); } while (0)

#define PASSCODE 20202021u
#define MAXQ 32
#define NCLI 8

typedef struct { uint8_t f[TI_FRAME_MAX]; size_t n; } dgram;
typedef struct {
    ti t;
    dgram q[MAXQ];
    int qh, qt;
    uint16_t port;
    int drop_rx, drop_tx;   /* frames to drop: node -> client, client -> node */
    uint32_t ent;
} cli;

static mt_node nodes[2];
static mt_node *N;
static uint32_t now;
static uint32_t node_ent;
static cli C[NCLI];
static size_t node_frames, node_resends;
static uint64_t seen[16];
static unsigned seen_n;
static uint8_t last_frame[TI_FRAME_MAX];
static size_t last_len;
#define LOGN 64
static dgram flog[LOGN];   /* every frame the node sent, oldest first (wraps) */
static unsigned flog_n;

static int ent_fn(void *ctx, uint8_t *out, size_t len)
{
    uint32_t *s = ctx;
    for (size_t i = 0; i < len; i++) {
        *s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5;
        out[i] = (uint8_t)*s;
    }
    return 0;
}

static uint32_t p_now(void *c) { (void)c; return now; }
static bool ent_down; /* the entropy source fails */
static int p_entropy(void *c, uint8_t *out, size_t len) { (void)c; return ent_down ? -1 : ent_fn(&node_ent, out, len); }

static uint64_t fnv(const uint8_t *p, size_t n)
{
    uint64_t h = 1469598103934665603ull;
    while (n--) h = (h ^ *p++) * 1099511628211ull;
    return h;
}

static cli *cli_by_port(uint16_t port)
{
    for (int i = 0; i < NCLI; i++) if (C[i].port == port) return &C[i];
    return NULL;
}

static void p_send(void *c, const mt_node_addr *to, mt_span f)
{
    (void)c;
    uint64_t h = fnv(f.p, f.len) + f.len;
    node_frames++;
    for (unsigned i = 0; i < seen_n && i < 16; i++) if (seen[i] == h) { node_resends++; break; }
    seen[seen_n++ % 16] = h;
    memcpy(flog[flog_n % LOGN].f, f.p, f.len);
    flog[flog_n % LOGN].n = f.len;
    flog_n++;
    cli *d = cli_by_port(to->port);
    if (!d) return;
    if (d->drop_rx > 0) { d->drop_rx--; return; }
    if ((d->qt + 1) % MAXQ == d->qh) return;
    memcpy(d->q[d->qt].f, f.p, f.len);
    d->q[d->qt].n = f.len;
    d->qt = (d->qt + 1) % MAXQ;
}

static void c_send(void *ctx, const uint8_t *frame, size_t len)
{
    cli *d = ctx;
    uint8_t buf[TI_FRAME_MAX];
    mt_node_addr a;
    if (d->drop_tx > 0) { d->drop_tx--; return; }
    memset(&a, 0, sizeof a);
    a.port = d->port;
    a.family = 6;
    memcpy(buf, frame, len);
    last_len = len;
    memcpy(last_frame, frame, len);
    mt_node_on_udp(N, &a, buf, len);
}

static size_t c_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t wait_ms)
{
    cli *d = ctx;
    if (d->qh == d->qt) {
        now += wait_ms;
        mt_node_poll(N);
    }
    if (d->qh == d->qt) return 0;
    size_t n = d->q[d->qh].n;
    if (n > cap) n = cap;
    memcpy(buf, d->q[d->qh].f, n);
    d->qh = (d->qh + 1) % MAXQ;
    return n;
}

static void cli_start(int i)
{
    cli *d = &C[i];
    if (d->port) ti_free(&d->t);
    memset(d, 0, sizeof *d);
    d->port = (uint16_t)(1000 + i);
    d->ent = 0x9E3779B9u * (uint32_t)(i + 1) + 12345u;
    ti_io io = { d, c_send, c_recv };
    ti_init(&d->t, io, ent_fn, &d->ent);
}

/* ---- kv fake (staged/applied, as the real port); survives a node restart unless the world is reset ---- */
#define KV_N 64
#define KV_CAP 512
typedef struct { uint16_t key, len; uint8_t d[KV_CAP]; bool used; } kent;
typedef struct { kent applied[KV_N], staged[KV_N]; bool dirty; } kvf;
static kvf KV;

static kent *kfind(kent *a, uint16_t key)
{
    for (int i = 0; i < KV_N; i++) if (a[i].used && a[i].key == key) return &a[i];
    return NULL;
}
static void ktouch(kvf *k) { if (!k->dirty) { memcpy(k->staged, k->applied, sizeof k->applied); k->dirty = true; } }
static mt_err k_get(void *c, uint16_t key, mt_buf out, size_t *len)
{
    kent *e = kfind(((kvf *)c)->applied, key);
    if (!e) return MT_ERR_NOT_FOUND;
    if (e->len > out.cap) return MT_ERR_BUFFER_TOO_SMALL;
    memcpy(out.p, e->d, e->len);
    *len = e->len;
    return MT_OK;
}
static mt_err k_set(void *c, uint16_t key, mt_span v)
{
    kvf *k = c;
    kent *e;
    if (v.len > KV_CAP) return MT_ERR_IO;
    ktouch(k);
    e = kfind(k->staged, key);
    for (int i = 0; !e && i < KV_N; i++) if (!k->staged[i].used) e = &k->staged[i];
    if (!e) return MT_ERR_IO;
    e->used = true; e->key = key; e->len = (uint16_t)v.len;
    memcpy(e->d, v.p, v.len);
    return MT_OK;
}
static mt_err k_del(void *c, uint16_t key)
{
    kvf *k = c;
    kent *e;
    ktouch(k);
    if ((e = kfind(k->staged, key)) != NULL) e->used = false;
    return MT_OK;
}
static mt_err k_finish(void *c, bool apply)
{
    kvf *k = c;
    if (apply && k->dirty) memcpy(k->applied, k->staged, sizeof k->applied);
    k->dirty = false;
    return MT_OK;
}
static const mt_kv_ops KVO = { &KV, k_get, k_set, k_del, k_finish };

/* ---- attestation: rs-matter's test DAC/PAI/CD (matter-root/test/attest.h) ---- */
static mt_err dac_sign(void *c, mt_span msg, uint8_t sig[MT_P256_SIG_LEN])
{
    return mt_crypto_p256_sign(c, a_dac_priv, msg, sig);
}
static mt_rng sign_rng;

/* ---- node fixture ---- */
static const uint8_t SALT[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
static mt_node_credentials CRED;
static const mt_basic_cfg BASIC = {
    "Test Vendor", 0xFFF1, "Test Thermostat", 0x8000, 7, "hw-7", 0x00010203, "1.2.3", "SN-0001", "uid-abc", 3, 3, 1,
};

static uint64_t g_event_base;
static unsigned mdns_calls;
static void p_mdns_changed(void *c) { (void)c; mdns_calls++; }
static mt_err (*g_opkey_gen)(void *ctx, uint8_t priv[MT_P256_SCALAR_LEN], uint8_t pub[MT_P256_POINT_LEN]);

/* BLE fakes (test_ble.inc) */
static bool g_ble;
static uint32_t g_ble_window_s;
static bool bp_send(void *c, mt_span pkt);
static void bp_close(void *c);
static void bp_window(void *c, bool open);
static const mt_netctl_ops NFO;
static void ble_pump(void);

static void node_start(mt_node *n, uint16_t im_len)
{
    mt_node_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.event_base = g_event_base;
    cfg.ports.now_ms = p_now;
    cfg.ports.udp_send = p_send;
    cfg.ports.entropy = p_entropy;
    cfg.ports.cred = &CRED;
    cfg.ports.kv = &KVO;
    cfg.ports.mdns_changed = p_mdns_changed;
    cfg.ports.opkey_gen = g_opkey_gen;
    if (g_ble) {
        cfg.ports.ble_send = bp_send;
        cfg.ports.ble_close = bp_close;
        cfg.ports.ble_window = bp_window;
        cfg.ports.net = &NFO;
        cfg.ble_window_s = g_ble_window_s;
    }
    cfg.basic = &BASIC;
    cfg.im_buf_len = im_len;
    CHECK(mt_node_init(n, &cfg) == MT_OK);
}

/* Restart the node on the same kv (a reboot); clients stay. */
static void reboot_node(uint16_t im_len)
{
    mt_rng_free(&N->rng);
    node_start(N, im_len);
}

static void world(uint16_t im_len)
{
    memset(&KV, 0, sizeof KV);
    mdns_calls = 0;
    for (int i = 0; i < NCLI; i++) if (C[i].port) { ti_free(&C[i].t); C[i].port = 0; }
    now = 5000;
    node_ent = 0x1234567u;
    node_frames = node_resends = 0;
    seen_n = 0;
    memset(seen, 0, sizeof seen);
    N = &nodes[0];
    node_start(N, im_len);
}

static unsigned used_exchanges(const mt_node *n)
{
    unsigned c = 0;
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++) c += n->xchg.xc[i].used;
    return c;
}

static void settle(uint32_t ms)
{
    for (uint32_t t = 0; t < ms; t += 100) {
        now += 100;
        mt_node_poll(N);
        if (g_ble) ble_pump();   /* the central's ack timers run too */
    }
}

static ti_path P(int32_t ep, int64_t cl, int64_t at) { ti_path p = { ep, cl, at }; return p; }

static bool str_is(const ti_attr *a, const char *s)
{
    return a && a->str_len == strlen(s) && memcmp(a->str, s, a->str_len) == 0;
}

/* ---- tests ---- */
static void test_pbkdf_vector(void)
{
    /* passcode 123456, salt 04a1d2c611f0bd3678677 97bfe823600, 2000 iterations: w0s || w1s from a chip-tool run. */
    static const uint8_t S[16] = { 0x04, 0xa1, 0xd2, 0xc6, 0x11, 0xf0, 0xbd, 0x36, 0x78, 0x67, 0x79, 0x7b, 0xfe, 0x82, 0x36, 0x00 };
    static const uint8_t W0S[40] = {
        0xc7, 0x89, 0x33, 0x9c, 0xc5, 0xeb, 0xbc, 0xf6, 0xdf, 0x04, 0xa9, 0x11, 0x11, 0x06, 0x4c, 0x15, 0xac, 0x5a, 0xea, 0x67,
        0x69, 0x9f, 0x32, 0x62, 0xcf, 0xc6, 0xe9, 0x19, 0xe8, 0xa4, 0x0b, 0xb3, 0x42, 0xe8, 0xc6, 0x8e, 0xa9, 0x9a, 0x73, 0xe2 };
    static const uint8_t W1S[40] = {
        0x59, 0xd1, 0x17, 0xd8, 0xed, 0xcb, 0x72, 0x8c, 0xbf, 0x3b, 0xa9, 0x88, 0x02, 0xd8, 0x45, 0x4b, 0xd0, 0x2d, 0xe5, 0xe4,
        0x1c, 0xc3, 0xd7, 0x00, 0x03, 0x3c, 0x86, 0x20, 0x9a, 0x42, 0x5f, 0x55, 0x96, 0x3b, 0x9f, 0x6f, 0x79, 0xef, 0xcb, 0x37 };
    mt_rng rng;
    uint32_t e = 77;
    uint8_t w0[32], w1[32], x0[32], x1[32];
    CHECK(mt_rng_init(&rng, ent_fn, &e) == MT_OK);
    CHECK(ti_passcode_to_w(&rng, 123456, mt_span_of(S, 16), 2000, w0, w1, NULL) == MT_OK);
    mt_crypto_p256_scalar_reduce(mt_span_of(W0S, 40), x0);
    mt_crypto_p256_scalar_reduce(mt_span_of(W1S, 40), x1);
    CHECK(memcmp(w0, x0, 32) == 0 && memcmp(w1, x1, 32) == 0);
    mt_rng_free(&rng);
}

static void test_init_errors(void)
{
    mt_node_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    CHECK(mt_node_init(&nodes[1], &cfg) == MT_ERR_INVALID);
    cfg.ports.now_ms = p_now; cfg.ports.udp_send = p_send; cfg.ports.entropy = p_entropy; cfg.ports.cred = &CRED;
    cfg.basic = &BASIC;
    CHECK(mt_node_init(&nodes[1], &cfg) == MT_ERR_INVALID);   /* no kv: fabrics need storage */
    cfg.ports.kv = &KVO;
    cfg.im_buf_len = 64;
    CHECK(mt_node_init(&nodes[1], &cfg) == MT_ERR_INVALID);
    cfg.im_buf_len = MT_NODE_IM_BUF_MAX + 1;
    CHECK(mt_node_init(&nodes[1], &cfg) == MT_ERR_INVALID);
    cfg.im_buf_len = 0;
    cfg.n_extra_eps = MT_NODE_MAX_EXTRA_EPS + 1;
    CHECK(mt_node_init(&nodes[1], &cfg) == MT_ERR_INVALID);
}

/* A failing reseed makes the DRBG refuse output: the transport still gets non-zero, non-repeating bytes, and the
 * failure is counted. */
static void test_rng_down(void)
{
    uint8_t a[20], b[20], z[20] = { 0 };
    world(0);
    mbedtls_ctr_drbg_set_reseed_interval(&N->rng.d, 1);
    ent_down = true;
    CHECK(mt_rng_fill(&N->rng, a, 1) != MT_OK);         /* the DRBG itself fails closed */
    uint32_t f0 = N->rng_failed;
    N->xchg.p.random(N->xchg.p.ctx, a, sizeof a);
    N->xchg.p.random(N->xchg.p.ctx, b, sizeof b);
    CHECK(N->rng_failed == f0 + 2 && memcmp(a, z, sizeof a) && memcmp(a, b, sizeof a));
    ent_down = false;
    mbedtls_ctr_drbg_set_reseed_interval(&N->rng.d, MBEDTLS_CTR_DRBG_RESEED_INTERVAL);
    N->xchg.p.random(N->xchg.p.ctx, a, sizeof a);
    CHECK(N->rng_failed == f0 + 2);                      /* back on the DRBG */
}

static void test_passcode_and_read(void)
{
    ti_report *rep = (ti_report *)calloc(1, sizeof *rep);
    uint32_t iters = 0;
    world(0);
    cli_start(0);
    ti *t = &C[0].t;

    CHECK(mt_node_window_open(N));
    /* wrong passcode fails, and the attempt is gone at once */
    CHECK(ti_pase(t, PASSCODE + 1, &iters) == MT_ERR_CRYPTO);
    CHECK(iters == CRED.iterations);
    settle(300);
    CHECK(!mt_node_pase_busy(N));
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 0);
    CHECK(!t->secure);

    /* the device's own check: Pake3 with a cA from the wrong passcode (the initiator is told to go on) */
    t->force_pake3 = true;
    CHECK(ti_pase(t, PASSCODE + 1, NULL) == MT_ERR_CRYPTO);
    t->force_pake3 = false;
    CHECK(t->status_general == 1 && t->status_code == 2);   /* FAILURE, INVALID_PARAMETER from the node */
    CHECK(!t->secure);
    settle(300);
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 0);
    CHECK(!mt_node_pase_busy(N));
    CHECK(used_exchanges(N) == 0);

    /* right passcode succeeds straight after */
    size_t before = node_frames;
    CHECK(ti_pase(t, PASSCODE, NULL) == MT_OK);
    CHECK(t->secure);
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 1);
    CHECK(!mt_node_pase_busy(N));
    CHECK(t->retransmits == 0);
    /* the device must not retransmit anything we acknowledged, and the unsecured exchange is released */
    size_t after = node_frames;
    CHECK(after - before >= 3);
    settle(6000);
    CHECK(node_frames == after);
    CHECK(node_resends == 0);
    CHECK(used_exchanges(N) == 0);

    /* Basic Information over the new session */
    ti_path p[3] = { P(0, 0x28, 1), P(0, 0x28, 4), P(0, 0x28, 9) };
    CHECK(ti_read(t, p, 3, rep) == MT_OK);
    CHECK(rep->chunks == 1 && rep->n == 3);
    CHECK(str_is(ti_find(rep, 0, 0x28, 1), "Test Vendor"));
    const ti_attr *pid = ti_find(rep, 0, 0x28, 4), *sw = ti_find(rep, 0, 0x28, 9);
    CHECK(pid && pid->val == 0x8000);
    CHECK(sw && sw->val == 0x00010203);
    /* Time Synchronization on endpoint 0: null until the device sets the time, then the Matter-epoch us */
    ti_path tp[3] = { P(0, 0x38, 0), P(0, 0x38, 1), P(0, 0x38, 2) };
    CHECK(mt_node_utc_now(N) == 0 && ti_read(t, tp, 3, rep) == MT_OK && rep->n == 3);
    CHECK(ti_find(rep, 0, 0x38, 0)->type == MT_TLV_NULL && ti_find(rep, 0, 0x38, 1)->val == 0 &&
          ti_find(rep, 0, 0x38, 2)->val == 0);
    CHECK(mt_node_set_utc(N, 700000000ull * 1000000ull, MT_TIME_GRAN_MS, MT_TIME_SRC_NONMATTER_SNTP) == MT_OK);
    CHECK(mt_node_set_utc(N, 1, MT_TIME_GRAN_NONE, MT_TIME_SRC_NONMATTER_SNTP) == MT_ERR_INVALID);
    CHECK(ti_read(t, tp, 3, rep) == MT_OK && rep->n == 3);
    CHECK(ti_find(rep, 0, 0x38, 0)->val >= 700000000ull * 1000000ull && mt_node_utc_now(N) >= 700000000u);
    CHECK(ti_find(rep, 0, 0x38, 1)->val == MT_TIME_GRAN_MS && ti_find(rep, 0, 0x38, 2)->val == MT_TIME_SRC_NONMATTER_SNTP);
    /* an unknown attribute is a status, not a crash */
    ti_path bad[1] = { P(0, 0x28, 0x7777) };
    CHECK(ti_read(t, bad, 1, rep) == MT_OK && rep->n == 1 && rep->a[0].is_status);
    settle(1000);
    CHECK(used_exchanges(N) == 0);

    /* CloseSession ends it; the keys are gone on the node */
    ti_close_session(t);
    settle(200);
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 0);
    free(rep);
}

static void test_chunked_wildcard(void)
{
    ti_report *big = calloc(1, sizeof *big), *small = calloc(1, sizeof *small);
    ti_path wild[1] = { P(0, -1, -1) };

    world(0);
    cli_start(0);
    CHECK(ti_pase(&C[0].t, PASSCODE, NULL) == MT_OK);
    CHECK(ti_read(&C[0].t, wild, 1, big) == MT_OK);
    CHECK(big->n > 20 && !big->overflow);

    world(MT_NODE_IM_BUF_MIN);   /* a 128-byte IM buffer: many chunks */
    cli_start(0);
    CHECK(ti_pase(&C[0].t, PASSCODE, NULL) == MT_OK);
    CHECK(ti_read(&C[0].t, wild, 1, small) == MT_OK);
    CHECK(small->chunks >= 4 && small->chunks > big->chunks);
    CHECK(!small->overflow);
    /* same data either way: every (cluster, attribute) of the big read is in the small one and vice versa,
     * and the values of the Basic Information strings agree */
    for (size_t i = 0; i < big->n; i++) {
        bool hit = false;
        CHECK(!big->a[i].is_status);
        for (size_t j = 0; j < small->n && !hit; j++)
            hit = small->a[j].cluster == big->a[i].cluster && small->a[j].attr == big->a[i].attr;
        CHECK(hit);
    }
    for (size_t j = 0; j < small->n; j++) {
        bool hit = false;
        CHECK(!small->a[j].is_status);
        for (size_t i = 0; i < big->n && !hit; i++)
            hit = small->a[j].cluster == big->a[i].cluster && small->a[j].attr == big->a[i].attr;
        CHECK(hit);
    }
    CHECK(str_is(ti_find(small, 0, 0x28, 1), "Test Vendor"));
    CHECK(str_is(ti_find(small, 0, 0x28, 3), "Test Thermostat"));
    const ti_attr *dm = ti_find(small, 0, 0x28, 0);
    CHECK(dm && dm->val == MT_BASIC_DATA_MODEL_REV);
    const ti_attr *sl = ti_find(small, 0, 0x1D, 1);   /* Descriptor ServerList: every endpoint-0 cluster */
    CHECK(sl == NULL || sl->val == N->eps[0].n_clusters); /* split into items when it did not fit one chunk */
    settle(2000);
    CHECK(used_exchanges(N) == 0);
    free(big);
    free(small);
}

static void test_loss(void)
{
    ti_report *rep = calloc(1, sizeof *rep);
    ti_path p[1] = { P(0, 0x28, 3) };

    /* the PBKDFParamResponse is lost: the device's MRP retransmits it */
    world(0);
    cli_start(0);
    C[0].drop_rx = 1;
    CHECK(ti_pase(&C[0].t, PASSCODE, NULL) == MT_OK);
    CHECK(node_resends >= 1);

    /* the secure ReportData is lost: retransmitted by the device */
    size_t r0 = node_resends;
    C[0].drop_rx = 1;
    CHECK(ti_read(&C[0].t, p, 1, rep) == MT_OK);
    CHECK(str_is(ti_find(rep, 0, 0x28, 3), "Test Thermostat"));
    CHECK(node_resends > r0);

    /* the request never arrives: the initiator resends it (the same message, so the node sees one request) */
    world(0);
    cli_start(0);
    C[0].drop_tx = 1;
    CHECK(ti_pase(&C[0].t, PASSCODE, NULL) == MT_OK);
    CHECK(C[0].t.retransmits >= 1);
    C[0].drop_tx = 1;
    CHECK(ti_read(&C[0].t, p, 1, rep) == MT_OK);
    CHECK(C[0].t.retransmits >= 2);

    /* the very same ReadRequest frame delivered twice: one ReportData, the repeat only re-acknowledged */
    {
        uint8_t rq[200], fr[TI_FRAME_MAX], copy[TI_FRAME_MAX], rbuf[TI_FRAME_MAX];
        size_t rl = ti_build_read_request(p, 1, rq, sizeof rq);
        uint16_t xid = 4321;
        size_t n = ti_build(&C[0].t, true, xid, MT_XCHG_RELIABLE, 1, 0x02, mt_span_of(rq, rl), 0, fr, sizeof fr);
        mt_node_addr a;
        unsigned reports = 0, acks = 0;
        size_t got;
        memset(&a, 0, sizeof a);
        a.port = C[0].port;
        CHECK(rl && n);
        memcpy(copy, fr, n);
        mt_node_on_udp(N, &a, copy, n);
        memcpy(copy, fr, n);
        mt_node_on_udp(N, &a, copy, n);
        while ((got = c_recv(&C[0], rbuf, sizeof rbuf, 0)) > 0) {
            ti_msg m;
            if (ti_parse(&C[0].t, rbuf, got, &m) == MT_OK && m.xid == xid) {
                reports += m.opcode == 0x05;
                acks += m.opcode == 0x10;
            }
        }
        CHECK(reports == 1);
        CHECK(acks <= 1);
        C[0].t.ack_owed = false;
        settle(61000);
        CHECK(used_exchanges(N) == 0);
    }
    free(rep);
}

/* Exchanges that die while IM waits on them (the peer vanishes mid-read) must be routed to
 * mt_im_on_exchange_failed: if they leaked, the two chunked-read slots would be gone after two abandoned reads. */
static void pase_hold(ti *t); /* PASE outliving the 60 s auto-armed fail-safe (defined with the invoke helpers) */
static void test_dying_exchanges(void)
{
    ti_report *rep = calloc(1, sizeof *rep);
    ti_path wild[1] = { P(0, -1, -1) };
    uint8_t rq[64];
    size_t rl = ti_build_read_request(wild, 1, rq, sizeof rq);
    world(MT_NODE_IM_BUF_MIN);
    cli_start(0);
    ti *t = &C[0].t;
    CHECK(ti_pase(t, PASSCODE, NULL) == MT_OK);
    pase_hold(t);
    CHECK(rl > 0);
    for (int i = 0; i < 4; i++) {
        ti_msg m;
        uint16_t xid = (uint16_t)(7000 + i);
        CHECK(ti_transact(t, true, xid, 1, 0x02, mt_span_of(rq, rl), &m) == MT_OK);
        CHECK(m.opcode == 0x05);
        CHECK(used_exchanges(N) == 1);          /* IM is waiting for our StatusResponse */
        if (i % 2 == 0) {
            ti_send_ack(t);                     /* acknowledged, then silence: the 60 s idle path */
            settle(61000);
        } else {
            t->ack_owed = false;                /* never acknowledged: MRP gives up (END_MRP) */
            settle(20000);
        }
        CHECK(used_exchanges(N) == 0);
        t->ack_owed = false;
        while (C[0].qh != C[0].qt) C[0].qh = (C[0].qh + 1) % MAXQ;   /* drop the retransmissions */
    }
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 1 || mt_node_session_count(N, MT_SESS_PASE) == 0);
    /* the session may have idled out of nothing; what matters is a full chunked read still works */
    if (!t->secure || mt_node_session_count(N, MT_SESS_PASE) == 0) {
        ti_free(t);
        cli_start(0);
        CHECK(ti_pase(&C[0].t, PASSCODE, NULL) == MT_OK);
    }
    CHECK(ti_read(&C[0].t, wild, 1, rep) == MT_OK);
    CHECK(rep->chunks >= 4 && !rep->overflow);
    for (size_t i = 0; i < rep->n; i++) CHECK(!rep->a[i].is_status);
    free(rep);
}

static void test_busy_and_attempts(void)
{
    world(0);
    cli_start(0);
    cli_start(1);
    cli_start(2);

    /* A opens an attempt and walks away; B is told BUSY */
    CHECK(ti_pase_params_only(&C[0].t) == MT_OK);
    ti_send_ack(&C[0].t);   /* acknowledged, then silent: only the 60 s timer can end it */
    CHECK(mt_node_pase_busy(N));
    CHECK(ti_pase(&C[1].t, PASSCODE, NULL) == MT_ERR_STATE);
    CHECK(C[1].t.status_general == 8 && C[1].t.status_code == 4);
    CHECK(C[1].t.status_data_len == 2 && mt_get_le16(C[1].t.status_data) == MT_NODE_BUSY_WAIT_MS);
    CHECK(mt_node_pase_busy(N));
    CHECK(used_exchanges(N) <= 1);   /* BUSY held no exchange */

    /* the 60 s timer frees the slot */
    now += MT_NODE_ATTEMPT_MS - 5000;
    mt_node_poll(N);
    CHECK(mt_node_pase_busy(N));
    now += 5000 + 10;
    mt_node_poll(N);
    CHECK(!mt_node_pase_busy(N));
    CHECK(used_exchanges(N) == 0);
    CHECK(ti_pase(&C[1].t, PASSCODE, NULL) == MT_OK);

    /* an attempt whose initiator went quiet for MT_NODE_STALL_MS gives way to a new one (and costs no guess) */
    uint8_t fa = N->failed_attempts;
    cli_start(4);
    CHECK(ti_pase_params_only(&C[4].t) == MT_OK);
    ti_send_ack(&C[4].t);
    now += MT_NODE_STALL_MS - 10;
    mt_node_poll(N);
    CHECK(ti_pase(&C[1].t, PASSCODE, NULL) == MT_ERR_STATE && C[1].t.status_general == 8);  /* still BUSY */
    now += 20;
    CHECK(ti_pase(&C[1].t, PASSCODE, NULL) == MT_OK);
    CHECK(N->failed_attempts == fa);

    /* every attempt gets a fresh session id; a newer PASE session replaces the older one */
    CHECK(ti_pase(&C[2].t, PASSCODE, NULL) == MT_OK);
    CHECK(C[1].t.peer_sid != C[2].t.peer_sid);
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 1);
    ti_report *rep = calloc(1, sizeof *rep);
    ti_path p[1] = { P(0, 0x28, 1) };
    CHECK(ti_read(&C[2].t, p, 1, rep) == MT_OK);
    CHECK(ti_read(&C[1].t, p, 1, rep) != MT_OK);   /* the replaced session is dead */

    /* window closed: no new attempt, the existing session lives on */
    mt_node_set_window(N, false);
    CHECK(!mt_node_window_open(N));
    cli_start(3);
    CHECK(ti_pase(&C[3].t, PASSCODE, NULL) == MT_ERR_TIMEOUT);
    CHECK(ti_read(&C[2].t, p, 1, rep) == MT_OK);
    mt_node_set_window(N, true);
    CHECK(ti_pase(&C[3].t, PASSCODE, NULL) == MT_OK);
    free(rep);
}

static void test_unsecured_policy(void)
{
    uint8_t buf[TI_FRAME_MAX], rq[200];
    world(0);
    cli_start(0);
    ti *t = &C[0].t;
    ti_path p[1] = { P(0, 0x28, 1) };
    size_t rl = ti_build_read_request(p, 1, rq, sizeof rq);
    size_t n = ti_build(t, false, 77, MT_XCHG_RELIABLE, 1, 0x02, mt_span_of(rq, rl), 0, buf, sizeof buf);
    CHECK(rl && n);

    /* an IM request on an unsecured session: dropped, no ack, no reply, no state */
    size_t f0 = node_frames;
    c_send(&C[0], buf, n);
    settle(1500);
    CHECK(node_frames == f0);
    CHECK(used_exchanges(N) == 0);
    CHECK(mt_node_session_count(N, MT_SESS_UNSECURED) == 0);

    /* a malformed Sigma1: INVALID_PARAMETER (chip CASESession::HandleSigma1), sent once and not retransmitted */
    ti_msg m;
    static const uint8_t junk[4] = { 0x15, 0x30, 0x01, 0x18 };
    f0 = node_frames;
    CHECK(ti_transact(t, false, 78, 0, 0x30, mt_span_of(junk, 4), &m) == MT_OK);
    CHECK(m.opcode == 0x40 && m.payload.len == 8);
    static const uint8_t want[8] = { 1, 0, 0, 0, 0, 0, 2, 0 };
    CHECK(m.payload.len == 8 && memcmp(m.payload.p, want, 8) == 0);
    ti_send_ack(t);
    settle(3000);
    CHECK(node_frames - f0 <= 2);
    CHECK(used_exchanges(N) == 0);
    CHECK(!mt_node_pase_busy(N));
}

/* Spoofed PBKDFParamRequests from many sources must not starve an established session. */
static void test_flood(void)
{
    ti_report *rep = calloc(1, sizeof *rep);
    ti_path p[1] = { P(0, 0x28, 1) };
    world(0);
    cli_start(0);
    CHECK(ti_pase(&C[0].t, PASSCODE, NULL) == MT_OK);

    for (int i = 0; i < 40; i++) {
        static ti f;
        static uint32_t fe;
        fe = 0xABCD0000u + (uint32_t)i * 7919u;
        ti_io io = { &C[7], c_send, NULL };   /* sends through client 7's port (unregistered: replies vanish) */
        io.recv = NULL;
        C[7].port = 0;
        ti_init(&f, io, ent_fn, &fe);
        /* one request, never acknowledged */
        uint8_t req[96], frame[TI_FRAME_MAX];
        mt_tlv_wr w;
        mt_span done;
        uint8_t ir[32] = { (uint8_t)i };
        mt_tlv_wr_init(&w, mt_buf_of(req, sizeof req));
        mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
        mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(ir, 32));
        mt_tlv_put_u(&w, mt_tlv_ctx(2), (uint64_t)(100 + i));
        mt_tlv_put_u(&w, mt_tlv_ctx(3), 0);
        mt_tlv_put_bool(&w, mt_tlv_ctx(4), false);
        mt_tlv_end(&w);
        mt_tlv_wr_done(&w, &done);
        size_t n = ti_build(&f, false, (uint16_t)(500 + i), MT_XCHG_RELIABLE, 0, 0x20, done, 0, frame, sizeof frame);
        CHECK(n > 0);
        c_send(&C[7], frame, n);
        ti_free(&f);
        CHECK(used_exchanges(N) <= MT_XCHG_N_EXCHANGES - MT_NODE_XC_RESERVE);
    }
    /* the established session still works, with the flood's retransmissions in flight */
    CHECK(ti_read(&C[0].t, p, 1, rep) == MT_OK);
    CHECK(str_is(ti_find(rep, 0, 0x28, 1), "Test Vendor"));
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 1);
    /* and once the flood gives up everything is released */
    settle(30000);
    CHECK(!mt_node_pase_busy(N));
    CHECK(used_exchanges(N) == 0);
    CHECK(ti_read(&C[0].t, p, 1, rep) == MT_OK);
    free(rep);
}

/* ---- review tests ---- */
#ifndef MT_NODE_MAX_FAILED_ATTEMPTS
#define MT_NODE_MAX_FAILED_ATTEMPTS 20
#endif

/* Online passcode guessing. An attempt that got as far as Pake2 has told the initiator whether its guess was
 * right (the prover checks cB itself, it never needs to send Pake3), so each such attempt must count; after
 * MT_NODE_MAX_FAILED_ATTEMPTS of them the commissioning window closes. Attempts that ended before Pake1 reveal
 * nothing and do not count. */
static void test_bruteforce(void)
{
    world(0);
    cli_start(0);
    ti *t = &C[0].t;
    for (int i = 0; i < 3; i++) {   /* PBKDFParamRequest only, then silence: no guess was made */
        CHECK(ti_pase_params_only(t) == MT_OK);
        ti_send_ack(t);
        now += MT_NODE_ATTEMPT_MS + 10;
        mt_node_poll(N);
        CHECK(!mt_node_pase_busy(N));
    }
    for (unsigned i = 0; i + 1 < MT_NODE_MAX_FAILED_ATTEMPTS; i++) {
        t->force_pake3 = (i & 1) != 0;   /* both the prover-side abort and the device-side cA rejection */
        CHECK(ti_pase(t, PASSCODE + 1 + i, NULL) == MT_ERR_CRYPTO);
    }
    t->force_pake3 = false;
    CHECK(mt_node_window_open(N));
    CHECK(ti_pase(t, PASSCODE + 777, NULL) == MT_ERR_CRYPTO);   /* the last allowed guess */
    CHECK(!mt_node_window_open(N));
    CHECK(ti_pase(t, PASSCODE, NULL) == MT_ERR_TIMEOUT);         /* even the right passcode is refused now */
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 0);
    mt_node_set_window(N, true);                                  /* a new window starts a new count */
    CHECK(ti_pase(t, PASSCODE + 1, NULL) == MT_ERR_CRYPTO);
    CHECK(mt_node_window_open(N));
    CHECK(ti_pase(t, PASSCODE, NULL) == MT_OK);
}

/* Buffer ownership: two chunked reads in flight share the IM chunk buffer. A's unacknowledged chunk must be
 * retransmitted byte-identical after B's chunk was built in the same IM buffer. */
static void test_interleaved_chunks(void)
{
    static dgram a_frame;
    ti_path wild[1] = { P(0, -1, -1) };
    uint8_t rq[64];
    size_t rl = ti_build_read_request(wild, 1, rq, sizeof rq);
    ti_msg m;
    world(MT_NODE_IM_BUF_MIN);
    cli_start(0);
    ti *t = &C[0].t;
    CHECK(ti_pase(t, PASSCODE, NULL) == MT_OK);
    CHECK(ti_transact(t, true, 8001, 1, 0x02, mt_span_of(rq, rl), &m) == MT_OK && m.opcode == 0x05);
    a_frame = flog[(flog_n - 1) % LOGN];
    t->ack_owed = false;                                         /* A's chunk 1 stays unacknowledged */
    unsigned mark = flog_n;
    CHECK(ti_transact(t, true, 8002, 1, 0x02, mt_span_of(rq, rl), &m) == MT_OK && m.opcode == 0x05);
    CHECK(memcmp(flog[(flog_n - 1) % LOGN].f, a_frame.f, a_frame.n) != 0);   /* B's chunk really differs */
    t->ack_owed = false;
    settle(1500);                                                /* MRP retransmits both */
    bool again = false;
    for (unsigned i = mark; i < flog_n && i < mark + LOGN; i++)
        again |= flog[i % LOGN].n == a_frame.n && memcmp(flog[i % LOGN].f, a_frame.f, a_frame.n) == 0;
    CHECK(again);
    settle(70000);
    while (C[0].qh != C[0].qt) C[0].qh = (C[0].qh + 1) % MAXQ;
    CHECK(used_exchanges(N) == 0);
}

/* Chunked read where the client's standalone ack for chunk 1 is lost, so its StatusResponse carries no ack.
 * The StatusResponse proves the chunk arrived, so xchg counts it as the ack and chunk 2 goes out. */
static void test_status_without_ack(void)
{
    ti_path wild[1] = { P(0, -1, -1) };
    uint8_t rq[64], sr[16];
    size_t rl = ti_build_read_request(wild, 1, rq, sizeof rq);
    mt_tlv_wr w;
    mt_span sr_span;
    ti_msg m;
    mt_tlv_wr_init(&w, mt_buf_of(sr, sizeof sr));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_u(&w, mt_tlv_ctx(0), 0);
    mt_tlv_put_u(&w, mt_tlv_ctx(255), 11);
    mt_tlv_end(&w);
    mt_tlv_wr_done(&w, &sr_span);
    world(MT_NODE_IM_BUF_MIN);
    cli_start(0);
    ti *t = &C[0].t;
    CHECK(ti_pase(t, PASSCODE, NULL) == MT_OK);
    CHECK(ti_transact(t, true, 8101, 1, 0x02, mt_span_of(rq, rl), &m) == MT_OK && m.opcode == 0x05);
    C[0].drop_tx = 1;
    ti_send_ack(t);                                              /* lost */
    CHECK(!t->ack_owed);
    mt_err e = ti_transact(t, true, 8101, 1, 0x01, sr_span, &m);
    CHECK(e == MT_OK && m.opcode == 0x05);                        /* chunk 2 */
    t->ack_owed = false;
    settle(70000);
    while (C[0].qh != C[0].qt) C[0].qh = (C[0].qh + 1) % MAXQ;
    CHECK(used_exchanges(N) == 0);
}

/* Event numbers must grow across reboots (controllers filter events below the last number they saw): the
 * port passes the persisted epoch, and this boot's StartUp event gets exactly that number. */
static uint64_t startup_number(const mt_node *n)
{
    for (unsigned i = 0; i < MT_IM_N_EVENTS; i++)
        if (n->im.events[i].number && n->im.events[i].cluster == MT_BASIC_CLUSTER_ID &&
            n->im.events[i].id == MT_BASIC_EVENT_STARTUP) return n->im.events[i].number;
    return 0;
}

static void test_event_epoch(void)
{
    world(0);
    CHECK(startup_number(N) == 1);                    /* no epoch: numbering starts at 1 */
    g_event_base = 0x30000;
    world(0);
    CHECK(startup_number(N) == 0x30000);
    CHECK(N->im.next_event == 0x30001);
    CHECK(mt_node_reboot_count(N) == 0);
    /* a reboot on the same storage: the BOOT record moves the epoch on by MT_NODE_EPOCH_STEP */
    g_event_base = 0;                                 /* ignored once the record exists */
    reboot_node(0);
    CHECK(startup_number(N) == 0x30000 + MT_NODE_EPOCH_STEP);
    CHECK(mt_node_reboot_count(N) == 1);
    reboot_node(0);
    CHECK(startup_number(N) == 0x30000 + 2 * MT_NODE_EPOCH_STEP);
    CHECK(mt_node_reboot_count(N) == 2);
}

/* IM state on an exchange the node closes itself. When IM's reply cannot be sent (no frame buffer free),
 * the node ends the exchange; xchg reports no on_close for a handler-initiated close, so the node must tell
 * IM, or what IM set up for that exchange (here a timed window) leaks for the session's lifetime. */
static size_t timed_request(uint8_t *out, size_t cap)
{
    mt_tlv_wr w;
    mt_span d;
    mt_tlv_wr_init(&w, mt_buf_of(out, cap));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_u(&w, mt_tlv_ctx(0), 5000);
    mt_tlv_put_u(&w, mt_tlv_ctx(255), 11);
    mt_tlv_end(&w);
    return mt_tlv_wr_done(&w, &d) == MT_OK ? d.len : 0;
}

static void test_reply_fails(void)
{
    ti_path wild[1] = { P(0, -1, -1) }, one[1] = { P(0, 0x28, 1) };
    uint8_t rq[64], rq1[64], tr[16], fr[TI_FRAME_MAX];
    size_t rl = ti_build_read_request(wild, 1, rq, sizeof rq), rl1 = ti_build_read_request(one, 1, rq1, sizeof rq1);
    size_t tl = timed_request(tr, sizeof tr);
    ti_msg m;
    world(MT_NODE_IM_BUF_MIN);
    cli_start(0);
    ti *t = &C[0].t;
    CHECK(ti_pase(t, PASSCODE, NULL) == MT_OK);
    pase_hold(t);
    /* three replies left unacknowledged hold all MT_XCHG_N_TXBUF frame buffers */
    CHECK(ti_transact(t, true, 9001, 1, 0x02, mt_span_of(rq, rl), &m) == MT_OK && m.opcode == 0x05);
    t->ack_owed = false;
    CHECK(ti_transact(t, true, 9002, 1, 0x02, mt_span_of(rq, rl), &m) == MT_OK && m.opcode == 0x05);
    t->ack_owed = false;
    CHECK(ti_transact(t, true, 9003, 1, 0x02, mt_span_of(rq1, rl1), &m) == MT_OK && m.opcode == 0x05);
    t->ack_owed = false;
    /* two TimedRequests now: IM opens a timed window for each, but its StatusResponse cannot go out */
    for (uint16_t x = 9004; x <= 9005; x++) {
        size_t n = ti_build(t, true, x, MT_XCHG_RELIABLE, 1, 0x0A, mt_span_of(tr, tl), 0, fr, sizeof fr);
        CHECK(n > 0);
        c_send(&C[0], fr, n);
    }
    settle(70000);                                  /* MRP gives up on the three replies; all released */
    while (C[0].qh != C[0].qt) C[0].qh = (C[0].qh + 1) % MAXQ;
    CHECK(used_exchanges(N) == 0);
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 1);
    /* a fresh TimedRequest must get a timed window (StatusResponse SUCCESS), not RESOURCE_EXHAUSTED */
    CHECK(ti_transact(t, true, 9006, 1, 0x0A, mt_span_of(tr, tl), &m) == MT_OK);
    CHECK(m.opcode == 0x01 && m.payload.len >= 4 && m.payload.p[0] == 0x15 && m.payload.p[1] == 0x24 &&
          m.payload.p[2] == 0x00);
    if (m.payload.len >= 4) { if (m.payload.p[3]) printf("  timed window refused: status 0x%02x\n", m.payload.p[3]); }
    CHECK(m.payload.len >= 4 && m.payload.p[3] == 0x00);
    t->ack_owed = false;
    settle(70000);
}

/* A subscription through the node: priming report, SubscribeResponse, then liveness reports on exchanges the
 * node opens. Guards the node's mt_im_on_exchange_failed call on handler-closed exchanges: it must not reap a
 * subscription whose report IM has just finished. */
static size_t status_ok(uint8_t *out, size_t cap)
{
    mt_tlv_wr w;
    mt_span d;
    mt_tlv_wr_init(&w, mt_buf_of(out, cap));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_u(&w, mt_tlv_ctx(0), 0);
    mt_tlv_put_u(&w, mt_tlv_ctx(255), 11);
    mt_tlv_end(&w);
    return mt_tlv_wr_done(&w, &d) == MT_OK ? d.len : 0;
}

static void test_subscription(void)
{
    uint8_t sub[64], sr[16], fr[TI_FRAME_MAX], rb[TI_FRAME_MAX];
    size_t srl = status_ok(sr, sizeof sr), sl;
    mt_tlv_wr w;
    mt_span d;
    ti_msg m;
    mt_tlv_wr_init(&w, mt_buf_of(sub, sizeof sub));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bool(&w, mt_tlv_ctx(0), false);
    mt_tlv_put_u(&w, mt_tlv_ctx(1), 0);
    mt_tlv_put_u(&w, mt_tlv_ctx(2), 2);
    mt_tlv_start(&w, mt_tlv_ctx(3), MT_TLV_ARRAY);
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_LIST);
    mt_tlv_put_u(&w, mt_tlv_ctx(2), 0);
    mt_tlv_put_u(&w, mt_tlv_ctx(3), 0x28);
    mt_tlv_put_u(&w, mt_tlv_ctx(4), 1);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    mt_tlv_put_bool(&w, mt_tlv_ctx(7), false);
    mt_tlv_put_u(&w, mt_tlv_ctx(255), 11);
    mt_tlv_end(&w);
    CHECK(mt_tlv_wr_done(&w, &d) == MT_OK);
    sl = d.len;

    world(0);
    cli_start(0);
    ti *t = &C[0].t;
    CHECK(ti_pase(t, PASSCODE, NULL) == MT_OK);
    CHECK(ti_transact(t, true, 9100, 1, 0x03, mt_span_of(sub, sl), &m) == MT_OK && m.opcode == 0x05);
    CHECK(ti_transact(t, true, 9100, 1, 0x01, mt_span_of(sr, srl), &m) == MT_OK && m.opcode == 0x04);
    ti_send_ack(t);
    CHECK(mt_im_sub_count(&N->im) == 1);
    unsigned live = 0;
    for (int i = 0; i < 40 && live < 3; i++) {
        size_t n = c_recv(&C[0], rb, sizeof rb, 250);
        if (!n || ti_parse(t, rb, n, &m) != MT_OK) continue;
        if (m.protocol != 1 || m.opcode != 0x05 || !(m.flags & MT_XCHG_INITIATOR)) continue;
        live++;                                       /* a liveness report: answer StatusResponse(SUCCESS) */
        size_t fl = ti_build_ex(t, true, m.xid, MT_XCHG_RELIABLE | MT_XCHG_ACK, 1, 0x01, mt_span_of(sr, srl),
                                m.counter, fr, sizeof fr);
        t->ack_owed = false;
        CHECK(fl > 0);
        c_send(&C[0], fr, fl);
        CHECK(mt_im_sub_count(&N->im) == 1);
    }
    CHECK(live == 3);
    CHECK(mt_im_sub_count(&N->im) == 1);
}

/* ---- commissioning over PASE then CASE (spec 5.5 steps; commands of 11.10 and 11.18) ---- */
static mt_err opkey_device(void *c, uint8_t priv[MT_P256_SCALAR_LEN], uint8_t pub[MT_P256_POINT_LEN])
{
    (void)c;
    ci_device_key(priv, pub);   /* the CSR key must match the public key of the test NOC Node01_02 */
    return MT_OK;
}

typedef struct { int status; uint32_t cmd; uint64_t f0, f1; } inv_res;   /* status -1: a response command came */
typedef void (*fields_fn)(mt_tlv_wr *w);

/* InvokeRequestMessage (8.8.2.9) with one CommandDataIB; parses the InvokeResponseIB (CommandDataIB fields 0/1
 * as unsigned, or the CommandStatusIB status). */
static mt_err invoke(ti *t, uint16_t ep, uint32_t cl, uint32_t cmd, fields_fn f, inv_res *res)
{
    uint8_t buf[900];
    mt_tlv_wr w;
    mt_tlv_rd r;
    mt_span s;
    ti_msg m;
    mt_err e;
    memset(res, 0, sizeof *res);
    res->status = -2;
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bool(&w, mt_tlv_ctx(0), false);
    mt_tlv_put_bool(&w, mt_tlv_ctx(1), false);
    mt_tlv_start(&w, mt_tlv_ctx(2), MT_TLV_ARRAY);
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_start(&w, mt_tlv_ctx(0), MT_TLV_LIST);
    mt_tlv_put_u(&w, mt_tlv_ctx(0), ep);
    mt_tlv_put_u(&w, mt_tlv_ctx(1), cl);
    mt_tlv_put_u(&w, mt_tlv_ctx(2), cmd);
    mt_tlv_end(&w);
    mt_tlv_start(&w, mt_tlv_ctx(1), MT_TLV_STRUCT);
    if (f) f(&w);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    mt_tlv_put_u(&w, mt_tlv_ctx(255), 11);
    mt_tlv_end(&w);
    if ((e = mt_tlv_wr_done(&w, &s))) return e;
    if ((e = ti_transact(t, true, t->next_xid++, 1, 0x08, s, &m))) return e;
    mt_tlv_rd_init(&r, m.payload);
    if (m.opcode == 0x01) {   /* StatusResponse { 0 status } */
        uint64_t v = 0;
        if (!mt_tlv_next(&r) && !mt_tlv_enter(&r) && !mt_tlv_find_ctx(&r, 0) && !mt_tlv_get_u64(&r, &v)) res->status = (int)v;
    } else if (m.opcode == 0x09 && !mt_tlv_next(&r) && !mt_tlv_enter(&r) && !mt_tlv_find_ctx(&r, 1) &&
               !mt_tlv_enter(&r) && !mt_tlv_next(&r) && !mt_tlv_enter(&r)) {
        while (!mt_tlv_next(&r)) {
            bool data = mt_tlv_is_ctx(&r, 0);
            if (mt_tlv_enter(&r)) break;
            while (!mt_tlv_next(&r)) {
                if (mt_tlv_is_ctx(&r, 0) || mt_tlv_is_ctx(&r, 1)) {
                    bool is1 = mt_tlv_is_ctx(&r, 1);
                    if (r.type != MT_TLV_STRUCT && r.type != MT_TLV_LIST) continue;
                    mt_tlv_enter(&r);
                    while (!mt_tlv_next(&r)) {
                        uint64_t v = 0;
                        if (mt_tlv_get_u64(&r, &v)) continue;
                        if (!data && is1 && mt_tlv_is_ctx(&r, 0)) res->status = (int)v;     /* StatusIB.status */
                        if (data && !is1 && mt_tlv_is_ctx(&r, 2)) res->cmd = (uint32_t)v;   /* CommandPath.command */
                        if (data && is1 && mt_tlv_is_ctx(&r, 0)) res->f0 = v;
                        if (data && is1 && mt_tlv_is_ctx(&r, 1)) res->f1 = v;
                    }
                    mt_tlv_exit(&r);
                }
            }
            mt_tlv_exit(&r);
            if (data) res->status = -1;
        }
    }
    ti_send_ack(t);
    return MT_OK;
}

static uint16_t g_failsafe_s;
static void f_arm(mt_tlv_wr *w) { mt_tlv_put_u(w, mt_tlv_ctx(0), g_failsafe_s); mt_tlv_put_u(w, mt_tlv_ctx(1), 0); }
/* A PASE session lives only as long as its fail-safe (60 s auto-armed): tests that idle longer arm the maximum. */
static void pase_hold(ti *t)
{
    inv_res r;
    g_failsafe_s = MT_ROOT_FAILSAFE_MAX_CUMULATIVE_S;
    CHECK(invoke(t, 0, 0x30, 0, f_arm, &r) == MT_OK && r.status == -1 && r.f0 == 0);
}
static void f_csr(mt_tlv_wr *w)
{
    uint8_t nonce[32];
    memset(nonce, 0x5a, sizeof nonce);
    mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(nonce, sizeof nonce));
}
static void f_root(mt_tlv_wr *w) { mt_tlv_put_bytes(w, mt_tlv_ctx(0), ci_root01()); }
static void f_noc(mt_tlv_wr *w)
{
    uint8_t ipk[16];
    memset(ipk, 0x4b, sizeof ipk);
    mt_tlv_put_bytes(w, mt_tlv_ctx(0), ci_noc_device());
    mt_tlv_put_bytes(w, mt_tlv_ctx(2), mt_span_of(ipk, sizeof ipk));
    mt_tlv_put_u(w, mt_tlv_ctx(3), CI_INITIATOR_NODE);   /* CaseAdminSubject: the CASE initiator below */
    mt_tlv_put_u(w, mt_tlv_ctx(4), 0xFFF1);
}

enum { GC = 0x30, OC = 0x3E, GC_ARM = 0, GC_ARM_RESP = 1, GC_COMPLETE = 4, GC_COMPLETE_RESP = 5, OC_CSR = 4,
       OC_CSR_RESP = 5, OC_NOC = 6, OC_NOC_RESP = 8, OC_ROOT = 11, IM_UNSUPPORTED_ACCESS = 0x7E };

/* PASE on t, then ArmFailSafe(fs_s), CSRRequest, AddTrustedRootCertificate, AddNOC. Returns the pending fabric. */
static const mt_fabric *commission_to_addnoc(ti *t, uint16_t fs_s, bool complete_before_noc)
{
    inv_res r;
    CHECK(ti_pase(t, PASSCODE, NULL) == MT_OK);
    g_failsafe_s = fs_s;
    CHECK(invoke(t, 0, GC, GC_ARM, f_arm, &r) == MT_OK && r.status == -1 && r.cmd == GC_ARM_RESP && r.f0 == 0);
    if (complete_before_noc) {
        /* fabric-scoped command without an accessing fabric (PASE before AddNOC): UNSUPPORTED_ACCESS */
        CHECK(invoke(t, 0, GC, GC_COMPLETE, NULL, &r) == MT_OK && r.status == IM_UNSUPPORTED_ACCESS);
    }
    CHECK(invoke(t, 0, OC, OC_CSR, f_csr, &r) == MT_OK && r.status == -1 && r.cmd == OC_CSR_RESP);
    CHECK(invoke(t, 0, OC, OC_ROOT, f_root, &r) == MT_OK && r.status == 0);
    /* FabricIndex 1 on a fresh node; an aborted earlier add may have used it (indexes aren't reused at once) */
    CHECK(invoke(t, 0, OC, OC_NOC, f_noc, &r) == MT_OK && r.status == -1 && r.cmd == OC_NOC_RESP && r.f0 == 0 &&
          r.f1 >= 1);
    return mt_fabric_pending(&N->fabrics);
}

/* The commissionable record's subtypes and TXT entries, byte for byte (spec 4.3.1). */
static void test_mdns_commissionable(void)
{
    mt_node_mdns_rec rec;
    char want[40];
    world(0);
    N->device_type = 0x0301;
    N->pairing_hint = 33;
    N->device_name = "A device name longer than thirty-two bytes";
    CHECK(mt_node_mdns_get(N, 0, &rec) && !rec.operational && strlen(rec.instance) == 16);
    CHECK(rec.n_sub == 4 && !strcmp(rec.sub[0], "_L3840") && !strcmp(rec.sub[1], "_S15") &&
          !strcmp(rec.sub[2], "_V65521") && !strcmp(rec.sub[3], "_CM"));
    CHECK(rec.n_txt == 9);
    CHECK(!strcmp(rec.txt[0], "D=3840") && !strcmp(rec.txt[1], "CM=1") && !strcmp(rec.txt[2], "VP=65521+32768"));
    CHECK(!strcmp(rec.txt[3], "DT=769") && !strcmp(rec.txt[4], "DN=A device name longer than thirty"));
    snprintf(want, sizeof want, "SII=%lu", (unsigned long)N->mrp_idle_ms);
    CHECK(!strcmp(rec.txt[5], want));
    snprintf(want, sizeof want, "SAI=%lu", (unsigned long)N->mrp_active_ms);
    CHECK(!strcmp(rec.txt[6], want));
    CHECK(!strcmp(rec.txt[7], "T=0") && !strcmp(rec.txt[8], "PH=33"));
}

static void test_case_commissioning(void)
{
    mt_node_mdns_rec rec;
    inv_res r;
    ti_report *rep = (ti_report *)calloc(1, sizeof *rep);
    g_opkey_gen = opkey_device;
    world(0);
    cli_start(0);
    cli_start(1);
    CHECK(mt_node_window_open(N));
    CHECK(mt_node_mdns_count(N) == 1);
    const mt_fabric *f = commission_to_addnoc(&C[0].t, 60, true);
    CHECK(f && f->pending && f->index == 1 && f->node_id == 0xDEDEDEDE00010002ull);
    if (!f) { free(rep); g_opkey_gen = NULL; return; }
    CHECK(mt_fabric_count(&N->fabrics) == 1);
    /* the pending fabric is advertised so the commissioner can find it for CASE (spec 4.3.1 / 5.5 step 13) */
    CHECK(mt_node_mdns_count(N) == 2);
    CHECK(mt_node_mdns_get(N, 0, &rec) && !rec.operational);
    CHECK(mt_node_mdns_get(N, 1, &rec) && rec.operational && strstr(rec.instance, "-DEDEDEDE00010002") != NULL);

    /* 11.10.7.6: CommissioningComplete over PASE (now with an accessing fabric) -> InvalidAuthentication */
    CHECK(invoke(&C[0].t, 0, GC, GC_COMPLETE, NULL, &r) == MT_OK && r.status == -1 && r.cmd == GC_COMPLETE_RESP &&
          r.f0 == MT_COMM_INVALID_AUTH);
    CHECK(mt_fabric_pending(&N->fabrics) != NULL);

    /* CASE to the pending fabric works before CommissioningComplete */
    CHECK(ci_case(&C[1].t, f) == MT_OK);
    CHECK(mt_node_session_count(N, MT_SESS_CASE) == 1);
    CHECK(ti_read(&C[1].t, (ti_path[]){ P(0, 0x3E, 5) }, 1, rep) == MT_OK);   /* CurrentFabricIndex */
    const ti_attr *a = ti_find(rep, 0, 0x3E, 5);
    CHECK(a && !a->is_status && a->val == 1);

    CHECK(invoke(&C[1].t, 0, GC, GC_COMPLETE, NULL, &r) == MT_OK && r.status == -1 && r.cmd == GC_COMPLETE_RESP &&
          r.f0 == 0);
    settle(11000);   /* past the doomed-session grace */
    CHECK(mt_fabric_pending(&N->fabrics) == NULL);
    CHECK(mt_fabric_count(&N->fabrics) == 1);
    CHECK(!mt_node_window_open(N));
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 0);
    CHECK(mt_node_session_count(N, MT_SESS_CASE) == 1);
    CHECK(mt_node_mdns_count(N) == 1);
    CHECK(mt_node_mdns_get(N, 0, &rec) && rec.operational);
    /* the CASE session keeps working after the commit */
    CHECK(ti_read(&C[1].t, (ti_path[]){ P(0, 0x3E, 5) }, 1, rep) == MT_OK);
    a = ti_find(rep, 0, 0x3E, 5);
    CHECK(a && a->val == 1);

    /* committed: survives a reboot, and the boot window stays closed */
    reboot_node(0);
    CHECK(mt_fabric_count(&N->fabrics) == 1 && mt_fabric_pending(&N->fabrics) == NULL);
    CHECK(!mt_node_window_open(N));
    g_opkey_gen = NULL;
    free(rep);
}

/* Fail-safe expiry (11.10.7.2 ArmFailSafe; 11.18.6 Operational Credentials on fail-safe expiry): the pending fabric is discarded, its CASE sessions closed and its
 * operational record withdrawn; nothing reaches storage. */
static void test_failsafe_expiry(void)
{
    mt_node_mdns_rec rec;
    mt_fabric copy;
    g_opkey_gen = opkey_device;
    world(0);
    cli_start(0);
    cli_start(1);
    cli_start(2);
    const mt_fabric *f = commission_to_addnoc(&C[0].t, 30, false);
    CHECK(f != NULL);
    if (!f) { g_opkey_gen = NULL; return; }
    copy = *f;
    CHECK(ci_case(&C[1].t, &copy) == MT_OK);
    CHECK(mt_node_session_count(N, MT_SESS_CASE) == 1);
    CHECK(mt_node_mdns_count(N) == 2);
    unsigned calls = mdns_calls;

    settle(31000);
    CHECK(mt_fabric_count(&N->fabrics) == 0 && mt_fabric_pending(&N->fabrics) == NULL);
    settle(11000);
    CHECK(mt_node_session_count(N, MT_SESS_CASE) == 0);
    CHECK(mdns_calls > calls);
    CHECK(mt_node_window_open(N));   /* the boot window (no timeout) is still open */
    CHECK(mt_node_mdns_count(N) == 1);
    CHECK(mt_node_mdns_get(N, 0, &rec) && !rec.operational);
    /* a new CASE attempt to the discarded fabric finds no trust root: NO_SHARED_TRUST_ROOTS (1, 0x0001) */
    CHECK(ci_case(&C[2].t, &copy) == MT_ERR_STATE);
    CHECK(C[2].t.status_general == 1 && C[2].t.status_code == 1);
    reboot_node(0);
    CHECK(mt_fabric_count(&N->fabrics) == 0);
    CHECK(mt_node_window_open(N));
    g_opkey_gen = NULL;
}

/* The PASE session's implicit Administer (spec 6.6.2.9) must not outlive the fail-safe. chip v1.3
 * CommissioningWindowManager: PASE establishment arms a 60 s fail-safe (OnSessionEstablished), its expiry or
 * ArmFailSafe(0) evicts the PASE session (OnPlatformEvent kFailSafeTimerExpired), and losing the PASE session
 * expires the fail-safe (OnSessionReleased), so a retry after a dropped commissioning starts clean. */
static void test_pase_lifetime(void)
{
    inv_res r;
    g_opkey_gen = opkey_device;
    /* (a) ArmFailSafe(0): answered, then the PASE session goes */
    world(0);
    cli_start(0);
    CHECK(ti_pase(&C[0].t, PASSCODE, NULL) == MT_OK);
    g_failsafe_s = 60;
    CHECK(invoke(&C[0].t, 0, GC, GC_ARM, f_arm, &r) == MT_OK && r.status == -1 && r.f0 == 0);
    g_failsafe_s = 0;
    CHECK(invoke(&C[0].t, 0, GC, GC_ARM, f_arm, &r) == MT_OK && r.status == -1 && r.cmd == GC_ARM_RESP && r.f0 == 0);
    settle(11000);
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 0);

    /* (b) a PASE session that never arms is still bounded (auto-armed at establishment) */
    world(0);
    cli_start(0);
    CHECK(ti_pase(&C[0].t, PASSCODE, NULL) == MT_OK);
    CHECK(mt_root_failsafe_armed(&N->root));
    settle(61000 + 11000);
    CHECK(!mt_root_failsafe_armed(&N->root) && mt_node_session_count(N, MT_SESS_PASE) == 0);

    /* (c) a dropped commissioning: PASE #1 got to AddNOC and closed its session; a retry on PASE #2 must not find
     * #1's pending fabric (BUSY) or its staged root (AddTrustedRootCertificate CONSTRAINT_ERROR) */
    world(0);
    cli_start(0);
    cli_start(1);
    CHECK(commission_to_addnoc(&C[0].t, 120, false) != NULL);
    ti_close_session(&C[0].t);
    settle(200);
    CHECK(mt_fabric_pending(&N->fabrics) == NULL && mt_fabric_count(&N->fabrics) == 0);
    CHECK(commission_to_addnoc(&C[1].t, 120, false) != NULL);

    /* (d) the same when PASE #2 simply replaces PASE #1 (no CloseSession) */
    world(0);
    cli_start(0);
    cli_start(1);
    CHECK(commission_to_addnoc(&C[0].t, 120, false) != NULL);
    CHECK(commission_to_addnoc(&C[1].t, 120, false) != NULL);
    g_opkey_gen = NULL;
}

#include "test_ble.inc"

int main(void)
{
    uint32_t e = 5;
    mt_rng rng;
    uint8_t w1[32];
    mt_rng_init(&rng, ent_fn, &e);
    CRED.salt = mt_span_of(SALT, sizeof SALT);
    CRED.iterations = 1000;
    CRED.discriminator = 3840;
    mt_rng_init(&sign_rng, ent_fn, &e);
    CRED.attest = (mt_root_creds){ mt_span_of(a_dac, sizeof a_dac), mt_span_of(a_pai, sizeof a_pai),
                                   mt_span_of(a_cd, sizeof a_cd), 0xFFF1, 0x8000, &sign_rng, dac_sign };
    CHECK(ti_passcode_to_w(&rng, PASSCODE, CRED.salt, CRED.iterations, CRED.w0, w1, CRED.l) == MT_OK);
    mt_rng_free(&rng);

    test_pbkdf_vector();
    test_init_errors();
    test_rng_down();
    test_passcode_and_read();
    test_mdns_commissionable();
    test_chunked_wildcard();
    test_loss();
    test_dying_exchanges();
    test_busy_and_attempts();
    test_unsecured_policy();
    test_flood();
    test_bruteforce();
    test_interleaved_chunks();
    test_status_without_ack();
    test_event_epoch();
    test_reply_fails();
    test_subscription();
    test_case_commissioning();
    test_failsafe_expiry();
    test_pase_lifetime();
    test_ble();
    printf("%d checks, %d failures, %d expected failures (sizeof(mt_node) = %zu)\n", checks, failures, xfails, sizeof(mt_node));
    return failures ? 1 : 0;
}
