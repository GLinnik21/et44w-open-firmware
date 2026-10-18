/* Host tests for the commissioning clusters of matter-root (General Commissioning, Operational Credentials, Access
 * Control, Group Key Management) and the access check. Everything runs through a real matter-dm tree via the
 * mt_im_dm boundary, with a real fabric table on an in-RAM kv fake and a fake node (sessions, clock, events).
 * Vectors: rs-matter's test DAC/PAI/CD (attest.h, from rs-matter commit c69916a test.rs; the DAC key signs) and
 * connectedhomeip's CHIPCert test certificates (matter-cert/test/vectors.h) with their operational private keys
 * (matter-case/test/keys.h). Expected status codes: spec 1.3 sections 11.10, 11.18, 9.10, 11.2 and 6.6.6 as
 * implemented by connectedhomeip v1.3 (see the cluster sources). */
#include <stdio.h>
#include <string.h>
#include "mt_root_comm.h"
#include "attest.h"
#include "keys.h"
#include "vectors.h"

extern int g_fail, g_checks;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
/* A known defect left open (listed in the review's open issues): counted, reported, not a failure. */
static int g_xfail;
#define XFAIL(c) do { g_checks++; if (!(c)) { g_xfail++; printf("XFAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } \
                      else printf("XPASS %s:%d: %s\n", __FILE__, __LINE__, #c); } while (0)

/* ---- kv fake (staged/applied, as the real port) ---- */

#define KV_N 48
#define KV_CAP 512
typedef struct { uint16_t key, len; uint8_t d[KV_CAP]; bool used; } kent;
typedef struct { kent applied[KV_N], staged[KV_N]; bool dirty; mt_err finish_err; } kvf;

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
    bool fail = apply && k->dirty && k->finish_err;   /* a failed apply leaves the applied state as it was */
    if (apply && k->dirty && !fail) memcpy(k->applied, k->staged, sizeof k->applied);
    k->dirty = false;
    return fail ? k->finish_err : MT_OK;
}

/* ---- the fake node ---- */

#define N_SESS 6
#define N_EV 16
enum { S_PASE = 1, S_CASE1 = 2, S_CASE2 = 3, S_CASE_OTHER = 4 };

typedef struct {
    kvf kv;
    mt_kv_ops kvo;
    mt_fabric_table t;
    mt_basic b;
    mt_root r;
    mt_root_creds creds;
    mt_root_ops ops;
    uint8_t scratch[MT_ROOT_SCRATCH];
    const mt_dm_cluster *cls0[10], *cls1[1];
    mt_dm_devtype t0[1], t1[1];
    mt_dm_endpoint eps[2];
    mt_dm_node node;
    mt_dm dm;
    /* node state */
    bool have[N_SESS];
    mt_root_session sess[N_SESS];
    uint32_t now;
    bool window;
    mt_err commit_err;
    int commits;
    struct { mt_root_event ev; uint8_t fabric; uint16_t session; uint8_t flags; } evs[N_EV];
    int n_ev;
    const uint8_t *key_priv, *key_pub;   /* the next CSRRequest key */
    int utc_calls;                       /* utc_set hook */
    uint64_t utc_us;
    uint8_t utc_gran, utc_src;
} fx;

static fx F; /* large (kv fake): static */
static mt_rng g_rng; /* outside F: an mbedtls DRBG context is not copied around */

static const mt_basic_cfg BCFG = { "V", 0xFFF1, "P", 0x8000, 1, "1", 1, "1", "S", "U", 3, 3, 1 };

static uint32_t o_now(void *c) { return ((fx *)c)->now; }
static bool o_session(void *c, uint16_t s, mt_root_session *out)
{
    fx *f = c;
    if (s >= N_SESS || !f->have[s]) return false;
    *out = f->sess[s];
    return true;
}
static void o_adopt(void *c, uint16_t s, uint8_t fabric) { ((fx *)c)->sess[s].fabric = fabric; }
static bool o_window(void *c) { return ((fx *)c)->window; }
static mt_err o_commit(void *c, uint8_t fabric) { fx *f = c; (void)fabric; f->commits++; return f->commit_err; }
static void o_event(void *c, mt_root_event ev, uint8_t fabric, uint16_t session, uint8_t flags)
{
    fx *f = c;
    if (f->n_ev < N_EV) {
        f->evs[f->n_ev].ev = ev; f->evs[f->n_ev].fabric = fabric;
        f->evs[f->n_ev].session = session; f->evs[f->n_ev].flags = flags;
        f->n_ev++;
    }
}
static mt_err o_opkey(void *c, uint8_t priv[MT_P256_SCALAR_LEN], uint8_t pub[MT_P256_POINT_LEN])
{
    fx *f = c;
    if (!f->key_priv) return MT_ERR_STATE;
    memcpy(priv, f->key_priv, MT_P256_SCALAR_LEN);
    memcpy(pub, f->key_pub, MT_P256_POINT_LEN);
    return MT_OK;
}
static void o_utc(void *c, uint64_t us, uint8_t gran, uint8_t src)
{
    fx *f = c;
    f->utc_calls++; f->utc_us = us; f->utc_gran = gran; f->utc_src = src;
}
static mt_err dac_sign(void *c, mt_span msg, uint8_t sig[MT_P256_SIG_LEN])
{
    return mt_crypto_p256_sign(c, a_dac_priv, msg, sig);
}
static int entropy(void *c, uint8_t *out, size_t len)
{
    (void)c;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(i * 31 + 7);
    return 0;
}

static bool g_rng_ready;

static void fx_session(int id, uint8_t auth, uint8_t fabric, uint64_t node)
{
    memset(&F.sess[id], 0, sizeof F.sess[id]);
    F.have[id] = true;
    F.sess[id].auth = auth;
    F.sess[id].fabric = fabric;
    F.sess[id].peer_node = node;
    for (int i = 0; i < MT_ROOT_CHALLENGE_LEN; i++) F.sess[id].challenge[i] = (uint8_t)(id * 16 + i);
}

/* A fresh node; keep_kv keeps the stored fabrics (reboot). */
static void fx_init(bool keep_kv)
{
    kvf saved;
    if (keep_kv) saved = F.kv;
    if (!g_rng_ready) { CHECK(mt_rng_init(&g_rng, entropy, NULL) == MT_OK); g_rng_ready = true; }
    memset(&F, 0, sizeof F);
    if (keep_kv) F.kv = saved;
    F.kvo = (mt_kv_ops){ &F.kv, k_get, k_set, k_del, k_finish };
    mt_fabric_init(&F.t, &F.kvo);
    CHECK(mt_fabric_load(&F.t, mt_buf_of(F.scratch, sizeof F.scratch)) == MT_OK);
    CHECK(mt_basic_init(&F.b, &BCFG, &F.kvo, 0x0001) == MT_OK);
    F.creds = (mt_root_creds){ mt_span_of(a_dac, sizeof a_dac), mt_span_of(a_pai, sizeof a_pai),
                               mt_span_of(a_cd, sizeof a_cd), 0xFFF1, 0x8000, &g_rng, dac_sign };
    F.ops = (mt_root_ops){ o_now, o_session, o_adopt, o_window, o_commit, o_event, o_opkey, o_utc };
    mt_root_cfg cfg = { &F.ops, &F, &F.t, &g_rng, &F.creds, &F.b, &F.kvo, 0x0021, MT_REG_INDOOR_OUTDOOR,
                        mt_buf_of(F.scratch, sizeof F.scratch) };
    CHECK(mt_root_init(&F.r, &cfg) == MT_OK);
    F.cls0[0] = &mt_dm_descriptor; F.cls0[1] = &F.b.cluster; F.cls0[2] = &F.r.acl;
    F.cls0[3] = &F.r.gencomm; F.cls0[4] = &F.r.opcreds; F.cls0[5] = &F.r.gkm; F.cls0[6] = &F.r.timesync;
    F.cls1[0] = &mt_dm_descriptor;
    F.t0[0] = (mt_dm_devtype){ 0x16, 1 };
    F.t1[0] = (mt_dm_devtype){ 0x301, 2 };
    F.eps[0] = (mt_dm_endpoint){ 0, 1, 7, 0, F.t0, F.cls0, NULL };
    F.eps[1] = (mt_dm_endpoint){ 1, 1, 1, 0, F.t1, F.cls1, NULL };
    F.node = (mt_dm_node){ F.eps, 2 };
    mt_dm_cfg dc = { &F.node, NULL, mt_root_access, &F.r, 1 };
    CHECK(mt_dm_init(&F.dm, &dc) == MT_OK);
    mt_root_bind_dm(&F.r, &F.dm);
    F.now = 1000;
}

static mt_im_subject subj(int id)
{
    mt_im_subject s = { (uint16_t)id, F.sess[id].auth, F.sess[id].fabric, F.sess[id].peer_node };
    return s;
}

/* ---- TLV helpers ---- */

static uint8_t g_req[1400], g_resp[1400], g_rd[1400];
static mt_tlv_wr g_w;

static mt_tlv_wr *req(void)
{
    mt_tlv_wr_init(&g_w, mt_buf_of(g_req, sizeof g_req));
    mt_tlv_start(&g_w, mt_tlv_anon(), MT_TLV_STRUCT);
    return &g_w;
}

/* Invoke cluster/cmd from session `sid` with the fields in g_w (or none when `w` is NULL). On a response command
 * *out is entered into its fields struct. Returns the status; *rc gets the response command id. */
static mt_im_status invoke(int sid, uint32_t cluster, uint32_t cmd, mt_tlv_wr *w, uint32_t *rc, mt_tlv_rd *out)
{
    mt_tlv_rd fields;
    mt_tlv_wr resp;
    mt_im_subject s = subj(sid);
    mt_im_cmd c = { 0, cluster, cmd };
    uint32_t rcmd = MT_IM_WILD_ID;
    mt_span sp;
    if (w) {
        mt_tlv_end(w);
        mt_tlv_rd_init(&fields, mt_tlv_wr_span(w));
        mt_tlv_next(&fields);
    } else {
        mt_tlv_rd_init(&fields, mt_span_of(NULL, 0));
    }
    mt_tlv_wr_init(&resp, mt_buf_of(g_resp, sizeof g_resp));
    mt_tlv_start(&resp, mt_tlv_ctx(1), MT_TLV_STRUCT);
    mt_im_status st = mt_dm_im.invoke(&F.dm, &s, &c, &fields, &resp, &rcmd);
    if (rc) *rc = rcmd;
    if (!st && rcmd != MT_IM_WILD_ID && out) {
        mt_tlv_end(&resp);
        mt_tlv_wr_done(&resp, &sp);
        mt_tlv_rd_init(out, sp);
        mt_tlv_next(out);
        mt_tlv_enter(out);
    }
    return st;
}

static bool field_u(mt_tlv_rd *s, uint8_t tag, uint64_t *v)
{
    mt_tlv_rd x = *s;
    return !mt_tlv_find_ctx(&x, tag) && !mt_tlv_get_u64(&x, v);
}
static bool field_b(mt_tlv_rd *s, uint8_t tag, mt_span *v)
{
    mt_tlv_rd x = *s;
    return !mt_tlv_find_ctx(&x, tag) && !mt_tlv_get_bytes(&x, v);
}
static bool has_field(mt_tlv_rd *s, uint8_t tag)
{
    mt_tlv_rd x = *s;
    return !mt_tlv_find_ctx(&x, tag);
}

/* Response code field 0 of a GeneralCommissioning / NOCResponse; -1 if the answer was not that response. */
static int code_of(mt_im_status st, uint32_t rc, uint32_t want_rc, mt_tlv_rd *o)
{
    uint64_t v;
    if (st || rc != want_rc || !field_u(o, 0, &v)) return -1;
    return (int)v;
}

static bool find_attr(uint32_t cluster, uint32_t id, mt_im_attr *a)
{
    for (uint16_t i = 0; !mt_dm_im.attr_at(&F.dm, i, a); i++)
        if (a->endpoint == 0 && a->cluster == cluster && a->attr == id) return true;
    return false;
}

/* Read item `item` of cluster/attr as session sid sees it; *out positioned on the value. */
static mt_err rd(int sid, bool filtered, uint32_t cluster, uint32_t attr, uint16_t item, mt_tlv_rd *out)
{
    mt_im_attr a;
    mt_tlv_wr w;
    mt_im_subject s = subj(sid);
    mt_im_rctx rc = { &s, filtered };
    if (!find_attr(cluster, attr, &a)) return MT_ERR_INVALID;
    mt_tlv_wr_init(&w, mt_buf_of(g_rd, sizeof g_rd));
    mt_err e = mt_dm_im.read(&F.dm, &rc, &a, item, &w, mt_tlv_anon());
    if (e) return e;
    mt_tlv_rd_init(out, mt_tlv_wr_span(&w));
    return mt_tlv_next(out);
}
static bool rd_u(uint32_t cluster, uint32_t attr, uint64_t want)
{
    mt_tlv_rd r;
    uint64_t v;
    return rd(S_PASE, false, cluster, attr, 0, &r) == MT_OK && !mt_tlv_get_u64(&r, &v) && v == want;
}
static unsigned list_len(int sid, bool filtered, uint32_t cluster, uint32_t attr)
{
    mt_tlv_rd r;
    unsigned n = 0;
    while (rd(sid, filtered, cluster, attr, (uint16_t)n, &r) == MT_OK) n++;
    return n;
}

static mt_im_status wr(int sid, uint32_t cluster, uint32_t attr, mt_im_wr_op op, mt_tlv_wr *w)
{
    mt_im_attr a;
    mt_tlv_rd v;
    mt_im_subject s = subj(sid);
    mt_im_wctx wc = { &s, false, false };
    if (!find_attr(cluster, attr, &a)) return 0xFFFF;
    mt_tlv_rd_init(&v, mt_tlv_wr_span(w));
    mt_tlv_next(&v);
    return mt_dm_im.write(&F.dm, &wc, &a, op, &v);
}

static mt_span tl(const char *name)
{
    for (size_t i = 0; i < sizeof VECS / sizeof VECS[0]; i++)
        if (!strcmp(VECS[i].name, name)) return mt_span_of(VECS[i].tlv, VECS[i].tlv_len);
    return mt_span_of(NULL, 0);
}
static const uint8_t *pubof(const char *name)
{
    for (size_t i = 0; i < sizeof VECS / sizeof VECS[0]; i++)
        if (!strcmp(VECS[i].name, name)) return VECS[i].pub;
    return NULL;
}
static uint64_t node_of(const char *noc)
{
    mt_cert c;
    return mt_cert_decode(tl(noc), &c) ? 0 : c.subject.node_id;
}
static uint64_t fabric_of(const char *noc)
{
    mt_cert c;
    return mt_cert_decode(tl(noc), &c) ? 0 : c.subject.fabric_id;
}
static bool span_eq(mt_span a, mt_span b) { return a.len == b.len && !memcmp(a.p, b.p, a.len); }
static bool contains(mt_span hay, const uint8_t *needle, size_t n)
{
    for (size_t i = 0; i + n <= hay.len; i++) if (!memcmp(hay.p + i, needle, n)) return true;
    return false;
}

/* ---- command shorthands ---- */

#define GC MT_GENCOMM_CLUSTER_ID
#define OC MT_OPCREDS_CLUSTER_ID
#define ACL MT_ACL_CLUSTER_ID
#define GKM MT_GKM_CLUSTER_ID

static int arm(int sid, uint16_t secs, uint64_t crumb)
{
    mt_tlv_wr *w = req();
    uint32_t rc;
    mt_tlv_rd o;
    mt_tlv_put_u(w, mt_tlv_ctx(0), secs);
    mt_tlv_put_u(w, mt_tlv_ctx(1), crumb);
    mt_im_status st = invoke(sid, GC, 0, w, &rc, &o);
    return code_of(st, rc, 1, &o);
}
static int complete(int sid, mt_im_status *st_out)
{
    uint32_t rc;
    mt_tlv_rd o;
    mt_im_status st = invoke(sid, GC, 4, NULL, &rc, &o);
    if (st_out) *st_out = st;
    return code_of(st, rc, 5, &o);
}

static const uint8_t NONCE[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                   17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

/* Signature {1} over elements {0} || the session's challenge, by the DAC. */
static bool dac_signed(int sid, mt_tlv_rd *o, mt_span *elements)
{
    mt_span el, sig;
    uint8_t msg[700];
    if (!field_b(o, 0, &el) || !field_b(o, 1, &sig) || sig.len != 64 || el.len + 16 > sizeof msg) return false;
    memcpy(msg, el.p, el.len);
    memcpy(msg + el.len, F.sess[sid].challenge, 16);
    *elements = el;
    return mt_crypto_p256_verify(a_dac_pub, mt_span_of(msg, el.len + 16), sig.p) == MT_OK;
}

static mt_im_status csr(int sid, const char *node, const uint8_t *priv, int update, mt_tlv_rd *o)
{
    mt_tlv_wr *w = req();
    uint32_t rc;
    F.key_priv = priv;
    F.key_pub = pubof(node);
    mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(NONCE, 32));
    if (update >= 0) mt_tlv_put_bool(w, mt_tlv_ctx(1), update);
    mt_im_status st = invoke(sid, OC, 4, w, &rc, o);
    return !st && rc != 5 ? 0xFFFF : st;
}
static mt_im_status add_trc(int sid, const char *root)
{
    mt_tlv_wr *w = req();
    mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl(root));
    return invoke(sid, OC, 11, w, NULL, NULL);
}
static const uint8_t IPK[16] = { 0x74, 0x65, 0x6d, 0x70, 0x6f, 0x72, 0x61, 0x72, 0x79, 0x20, 0x69, 0x70, 0x6b, 0x20, 0x30, 0x31 };
/* AddNOC; returns the NOCResponse status code (or -1 when answered with a status, then *st holds it). */
static int add_noc_x(int sid, const char *noc, const char *icac, size_t ipk_len, uint64_t admin, uint16_t vendor,
                     mt_im_status *st_out, uint8_t *index)
{
    mt_tlv_wr *w = req();
    uint32_t rc;
    mt_tlv_rd o;
    uint64_t v;
    mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl(noc));
    if (icac) mt_tlv_put_bytes(w, mt_tlv_ctx(1), tl(icac));
    mt_tlv_put_bytes(w, mt_tlv_ctx(2), mt_span_of(IPK, ipk_len));
    mt_tlv_put_u(w, mt_tlv_ctx(3), admin);
    mt_tlv_put_u(w, mt_tlv_ctx(4), vendor);
    mt_im_status st = invoke(sid, OC, 6, w, &rc, &o);
    if (st_out) *st_out = st;
    int code = code_of(st, rc, 8, &o);
    if (index) *index = field_u(&o, 1, &v) ? (uint8_t)v : 0;
    if (code > 0 && has_field(&o, 1)) return 100; /* FabricIndex only with OK */
    return code;
}
static int add_noc(int sid, const char *noc, const char *icac, uint64_t admin, uint8_t *index)
{
    return add_noc_x(sid, noc, icac, 16, admin, 0xFFF1, NULL, index);
}
static int label_n(int sid, const char *s, size_t n, mt_im_status *st)
{
    mt_tlv_wr *w = req();
    uint32_t rc;
    mt_tlv_rd o;
    mt_tlv_put_utf8(w, mt_tlv_ctx(0), s, n);
    mt_im_status x = invoke(sid, OC, 9, w, &rc, &o);
    if (st) *st = x;
    return code_of(x, rc, 8, &o);
}
static int label(int sid, const char *s, mt_im_status *st) { return label_n(sid, s, strlen(s), st); }
static int remove_fabric(int sid, unsigned idx, mt_im_status *st, bool *has_index)
{
    mt_tlv_wr *w = req();
    uint32_t rc;
    mt_tlv_rd o;
    mt_tlv_put_u(w, mt_tlv_ctx(0), idx);
    mt_im_status x = invoke(sid, OC, 10, w, &rc, &o);
    if (st) *st = x;
    if (has_index) *has_index = !x && has_field(&o, 1);
    return code_of(x, rc, 8, &o);
}
static bool saw(mt_root_event ev, uint8_t fabric)
{
    for (int i = 0; i < F.n_ev; i++) if (F.evs[i].ev == ev && F.evs[i].fabric == fabric) return true;
    return false;
}

/* Commission Root01 / Node01_02 (no ICAC) over PASE and complete over CASE: fabric 1, admin node 0x1122. */
#define ADMIN1 0x1122ull
static void commission_first(void)
{
    mt_tlv_rd o;
    uint8_t idx = 0;
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    CHECK(arm(S_PASE, 60, 1) == MT_COMM_OK);
    CHECK(csr(S_PASE, "Node01_02", k_Node01_02_priv, -1, &o) == MT_IM_SUCCESS);
    CHECK(add_trc(S_PASE, "Root01") == MT_IM_SUCCESS);
    CHECK(add_noc(S_PASE, "Node01_02", NULL, ADMIN1, &idx) == MT_NOC_OK && idx == 1);
    fx_session(S_CASE1, MT_IM_AUTH_CASE, 1, ADMIN1);
    CHECK(complete(S_CASE1, NULL) == MT_COMM_OK);
}

/* ---- tests ---- */

static void test_gencomm_attrs(void)
{
    mt_tlv_rd r, x;
    uint64_t v;
    bool b;
    fx_init(false);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    CHECK(rd(S_PASE, false, GC, 1, 0, &r) == MT_OK && r.type == MT_TLV_STRUCT);
    x = r; mt_tlv_enter(&x);
    CHECK(field_u(&x, 0, &v) && v == 60 && field_u(&x, 1, &v) && v == 900);
    CHECK(rd_u(GC, 0, 0));                            /* Breadcrumb */
    CHECK(rd_u(GC, 2, MT_REG_INDOOR));                /* RegulatoryConfig default with IndoorOutdoor capability */
    CHECK(rd_u(GC, 3, MT_REG_INDOOR_OUTDOOR));        /* LocationCapability */
    CHECK(rd(S_PASE, false, GC, 4, 0, &r) == MT_OK && !mt_tlv_get_bool(&r, &b) && b);
    CHECK(rd_u(GC, 0xFFFD, 1) && rd_u(OC, 0xFFFD, 1) && rd_u(ACL, 0xFFFD, 1) && rd_u(GKM, 0xFFFD, 2));
    CHECK(list_len(S_PASE, false, OC, 0xFFF9) == 8 && list_len(S_PASE, false, OC, 0xFFF8) == 4);
    CHECK(list_len(S_PASE, false, GC, 0xFFF9) == 3 && list_len(S_PASE, false, GC, 0xFFF8) == 3);
    CHECK(list_len(S_PASE, false, GKM, 0xFFF9) == 4 && list_len(S_PASE, false, GKM, 0xFFF8) == 2);
    CHECK(list_len(S_PASE, false, ACL, 0xFFF9) == 0 && list_len(S_PASE, false, ACL, 0xFFFB) == 4 + 5);
    mt_im_attr a;
    CHECK(find_attr(GC, 0, &a) && (a.flags & MT_IM_ATTR_WRITABLE) && a.write_priv == MT_IM_PRIV_ADMINISTER);
    CHECK(find_attr(OC, 0, &a) && a.read_priv == MT_IM_PRIV_ADMINISTER && (a.flags & MT_IM_ATTR_LIST));
    CHECK(find_attr(ACL, 0, &a) && a.read_priv == MT_IM_PRIV_ADMINISTER && a.write_priv == MT_IM_PRIV_ADMINISTER);
    CHECK(find_attr(GKM, 0, &a) && a.write_priv == MT_IM_PRIV_MANAGE);
    /* Breadcrumb write */
    mt_tlv_wr w;
    uint8_t buf[16];
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_tlv_put_u(&w, mt_tlv_anon(), 0x123456789ull);
    CHECK(wr(S_PASE, GC, 0, MT_IM_WR_VALUE, &w) == MT_IM_SUCCESS && rd_u(GC, 0, 0x123456789ull));
}

static void test_regulatory(void)
{
    mt_tlv_wr *w;
    uint32_t rc;
    mt_tlv_rd o;
    fx_init(false);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
#define SETREG(loc, cc, crumb) (w = req(), mt_tlv_put_u(w, mt_tlv_ctx(0), loc), \
    mt_tlv_put_utf8(w, mt_tlv_ctx(1), cc, strlen(cc)), mt_tlv_put_u(w, mt_tlv_ctx(2), crumb), \
    invoke(S_PASE, GC, 2, w, &rc, &o))
    CHECK(SETREG(MT_REG_OUTDOOR, "DE", 7) == MT_IM_SUCCESS && code_of(0, rc, 3, &o) == MT_COMM_OK);
    CHECK(has_field(&o, 1)); /* DebugText */
    CHECK(rd_u(GC, 2, MT_REG_OUTDOOR) && rd_u(GC, 0, 7) && !strcmp(F.b.location, "DE"));
    CHECK(SETREG(MT_REG_INDOOR, "DEU", 8) == MT_IM_CONSTRAINT_ERROR && rd_u(GC, 0, 7));
    CHECK(SETREG(3, "FR", 9) == MT_IM_SUCCESS && code_of(0, rc, 3, &o) == MT_COMM_VALUE_OUTSIDE_RANGE);
    CHECK(rd_u(GC, 2, MT_REG_OUTDOOR) && rd_u(GC, 0, 7) && !strcmp(F.b.location, "DE"));
    w = req();
    CHECK(invoke(S_PASE, GC, 2, w, &rc, &o) == MT_IM_INVALID_COMMAND);
    /* persisted across a reboot */
    fx_init(true);
    CHECK(rd_u(GC, 2, MT_REG_OUTDOOR) && !strcmp(F.b.location, "DE") && rd_u(GC, 0, 0));
    /* a fixed capability: only that value is accepted */
    F.r.c.location_cap = MT_REG_INDOOR;
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    CHECK(SETREG(MT_REG_OUTDOOR, "DE", 1) == MT_IM_SUCCESS && code_of(0, rc, 3, &o) == MT_COMM_VALUE_OUTSIDE_RANGE);
    CHECK(SETREG(MT_REG_INDOOR, "US", 1) == MT_IM_SUCCESS && code_of(0, rc, 3, &o) == MT_COMM_OK);
#undef SETREG
}

static void test_attestation(void)
{
    mt_tlv_wr *w;
    uint32_t rc;
    mt_tlv_rd o, e;
    mt_span el = { NULL, 0 }, v;
    uint64_t ts;
    fx_init(false);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    /* CertificateChainRequest (no fail-safe needed) */
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), 1);
    CHECK(invoke(S_PASE, OC, 2, w, &rc, &o) == MT_IM_SUCCESS && rc == 3 && field_b(&o, 0, &v) &&
          span_eq(v, mt_span_of(a_dac, sizeof a_dac)));
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), 2);
    CHECK(invoke(S_PASE, OC, 2, w, &rc, &o) == MT_IM_SUCCESS && rc == 3 && field_b(&o, 0, &v) &&
          span_eq(v, mt_span_of(a_pai, sizeof a_pai)));
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), 3);
    CHECK(invoke(S_PASE, OC, 2, w, &rc, &o) == MT_IM_INVALID_COMMAND);
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), 0);
    CHECK(invoke(S_PASE, OC, 2, w, &rc, &o) == MT_IM_INVALID_COMMAND);
    /* AttestationRequest: elements {1: CD, 2: nonce, 3: timestamp}, DAC signature over elements || challenge */
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(NONCE, 32));
    CHECK(invoke(S_PASE, OC, 0, w, &rc, &o) == MT_IM_SUCCESS && rc == 1);
    CHECK(dac_signed(S_PASE, &o, &el));
    mt_tlv_rd_init(&e, el);
    CHECK(!mt_tlv_next(&e) && e.type == MT_TLV_STRUCT && !mt_tlv_enter(&e));
    CHECK(field_b(&e, 1, &v) && span_eq(v, mt_span_of(a_cd, sizeof a_cd)));
    CHECK(field_b(&e, 2, &v) && span_eq(v, mt_span_of(NONCE, 32)));
    CHECK(field_u(&e, 3, &ts) && ts == 0);
    /* the signature is bound to the session's challenge */
    F.sess[S_PASE].challenge[0] ^= 1;
    CHECK(!dac_signed(S_PASE, &o, &el));
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(NONCE, 31));
    CHECK(invoke(S_PASE, OC, 0, w, &rc, &o) == MT_IM_INVALID_COMMAND);
    w = req();
    CHECK(invoke(S_PASE, OC, 0, w, &rc, &o) == MT_IM_INVALID_COMMAND);
    F.have[S_PASE] = false; /* the node lost the session */
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(NONCE, 32));
    CHECK(invoke(S_PASE, OC, 0, w, &rc, &o) == MT_IM_FAILURE);
}

static void test_full_commissioning(void)
{
    mt_tlv_rd o, e, x;
    mt_span el = { NULL, 0 }, v;
    mt_im_status st;
    uint8_t idx = 0;
    uint64_t u;
    fx_init(false);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    /* everything that needs the fail-safe */
    CHECK(csr(S_PASE, "Node01_02", k_Node01_02_priv, -1, &o) == MT_IM_FAILSAFE_REQUIRED);
    CHECK(add_trc(S_PASE, "Root01") == MT_IM_FAILSAFE_REQUIRED);
    CHECK(add_noc_x(S_PASE, "Node01_02", NULL, 16, ADMIN1, 0xFFF1, &st, NULL) == -1 && st == MT_IM_FAILSAFE_REQUIRED);
    CHECK(complete(S_PASE, &st) == -1 && st == MT_IM_UNSUPPORTED_ACCESS); /* fabric-scoped, no fabric yet */

    CHECK(arm(S_PASE, 60, 1) == MT_COMM_OK && rd_u(GC, 0, 1));
    /* CSRRequest: NOCSRElements {1: CSR with the new key, 2: nonce}, DAC-signed */
    CHECK(csr(S_PASE, "Node01_02", k_Node01_02_priv, 1, &o) == MT_IM_INVALID_COMMAND); /* for update over PASE */
    CHECK(csr(S_PASE, "Node01_02", k_Node01_02_priv, 0, &o) == MT_IM_SUCCESS);
    CHECK(dac_signed(S_PASE, &o, &el));
    mt_tlv_rd_init(&e, el);
    CHECK(!mt_tlv_next(&e) && !mt_tlv_enter(&e));
    CHECK(field_b(&e, 1, &v) && contains(v, pubof("Node01_02"), 65));
    CHECK(field_b(&e, 2, &v) && span_eq(v, mt_span_of(NONCE, 32)));
    CHECK(F.t.pend.has_key && !memcmp(F.t.pend.pub, pubof("Node01_02"), 65));
    /* AddNOC before AddTrustedRootCertificate */
    CHECK(add_noc(S_PASE, "Node01_02", NULL, ADMIN1, NULL) == MT_NOC_INVALID_NOC);
    CHECK(add_trc(S_PASE, "ICA01") == MT_IM_INVALID_COMMAND);   /* not a root */
    CHECK(add_trc(S_PASE, "Root01") == MT_IM_SUCCESS);
    CHECK(add_trc(S_PASE, "Root01") == MT_IM_CONSTRAINT_ERROR); /* once per fail-safe */
    CHECK(list_len(S_PASE, false, OC, 4) == 1 && rd(S_PASE, false, OC, 4, 0, &x) == MT_OK &&
          !mt_tlv_get_bytes(&x, &v) && span_eq(v, tl("Root01")));
    /* AddNOC argument checks */
    CHECK(add_noc_x(S_PASE, "Node01_02", NULL, 15, ADMIN1, 0xFFF1, &st, NULL) == -1 && st == MT_IM_INVALID_COMMAND);
    CHECK(add_noc_x(S_PASE, "Node01_02", NULL, 16, ADMIN1, 0, &st, NULL) == -1 && st == MT_IM_INVALID_COMMAND);
    CHECK(add_noc_x(S_PASE, "Node01_02", NULL, 16, ADMIN1, 0xFFF5, &st, NULL) == -1 && st == MT_IM_INVALID_COMMAND);
    CHECK(add_noc(S_PASE, "Node01_02", NULL, 0, NULL) == MT_NOC_INVALID_ADMIN_SUBJECT);
    CHECK(add_noc(S_PASE, "Node01_02", NULL, 0xFFFFFFFFFFFF0001ull, NULL) == MT_NOC_INVALID_ADMIN_SUBJECT); /* group */
    CHECK(add_noc(S_PASE, "Node01_01", "ICA01", ADMIN1, NULL) == MT_NOC_INVALID_PUBLIC_KEY); /* not the CSR key */
    /* chip order: the chain is validated before the key (ValidateIncomingNOCChain -> InvalidNOC) */
    CHECK(add_noc(S_PASE, "Node02_01", "ICA02", ADMIN1, NULL) == MT_NOC_INVALID_NOC);
    CHECK(add_noc(S_PASE, "Node01_01", NULL, ADMIN1, NULL) == MT_NOC_INVALID_NOC); /* ICAC missing, wrong key too */
    CHECK(add_noc(S_PASE, "Node01_02", "ICA01", ADMIN1, NULL) == MT_NOC_INVALID_NOC);        /* wrong chain */
    CHECK(mt_fabric_count(&F.t) == 0 && F.n_ev == 0);
    /* AddNOC */
    CHECK(add_noc(S_PASE, "Node01_02", NULL, ADMIN1, &idx) == MT_NOC_OK && idx == 1);
    CHECK(F.sess[S_PASE].fabric == 1 && F.r.fs.fabric == 1 && (F.r.fs.flags & MT_FS_ADD_NOC));
    CHECK(saw(MT_ROOT_EV_FABRIC_ADDED, 1));
    CHECK(add_noc(S_PASE, "Node01_02", NULL, ADMIN1, NULL) == -1);                  /* a second NOC command */
    CHECK(add_noc_x(S_PASE, "Node01_02", NULL, 16, ADMIN1, 0xFFF1, &st, NULL) == -1 && st == MT_IM_CONSTRAINT_ERROR);
    CHECK(csr(S_PASE, "Node01_02", k_Node01_02_priv, 0, &o) == MT_IM_CONSTRAINT_ERROR);
    CHECK(add_trc(S_PASE, "Root02") == MT_IM_CONSTRAINT_ERROR);
    CHECK(rd_u(OC, 3, 1) && rd_u(OC, 2, 3));                                         /* Commissioned, Supported */
    CHECK(list_len(S_PASE, false, OC, 4) == 1);                                       /* the root now as the fabric's */
    /* the pending fabric is visible: label, Fabrics, NOCs, ACL */
    CHECK(label(S_PASE, "0123456789012345678901234567890123", &st) == -1 && st == MT_IM_INVALID_COMMAND);
    CHECK(label(S_PASE, "Home", NULL) == MT_NOC_OK);
    CHECK(rd(S_PASE, true, OC, 1, 0, &x) == MT_OK && !mt_tlv_enter(&x));
    CHECK(field_b(&x, 1, &v) && span_eq(v, mt_span_of(pubof("Root01"), 65)));
    CHECK(field_u(&x, 2, &u) && u == 0xFFF1 && field_u(&x, 3, &u) && u == 0xFAB000000000001Dull);
    CHECK(field_u(&x, 4, &u) && u == node_of("Node01_02") && field_u(&x, 254, &u) && u == 1);
    {
        mt_tlv_rd y = x;
        mt_span lab;
        CHECK(!mt_tlv_find_ctx(&y, 5) && !mt_tlv_get_utf8(&y, &lab) && lab.len == 4 && !memcmp(lab.p, "Home", 4));
    }
    CHECK(rd(S_PASE, true, OC, 0, 0, &x) == MT_OK && !mt_tlv_enter(&x));
    CHECK(field_b(&x, 1, &v) && span_eq(v, tl("Node01_02")));
    {
        mt_tlv_rd y = x;
        CHECK(!mt_tlv_find_ctx(&y, 2) && y.type == MT_TLV_NULL); /* no ICAC */
    }
    CHECK(rd_u(OC, 5, 1)); /* CurrentFabricIndex of the PASE session after AddNOC */
    CHECK(rd(S_PASE, true, ACL, 0, 0, &x) == MT_OK && !mt_tlv_enter(&x));
    CHECK(field_u(&x, 1, &u) && u == MT_ACL_PRIV_ADMINISTER && field_u(&x, 2, &u) && u == MT_ACL_AUTH_CASE);
    CHECK(field_u(&x, 254, &u) && u == 1);
    {
        mt_tlv_rd y = x;
        CHECK(!mt_tlv_find_ctx(&y, 3) && !mt_tlv_enter(&y) && !mt_tlv_next(&y) && !mt_tlv_get_u64(&y, &u) && u == ADMIN1);
    }
    /* CommissioningComplete: not over PASE; over CASE of the fabric */
    CHECK(complete(S_PASE, NULL) == MT_COMM_INVALID_AUTH);
    fx_session(S_CASE_OTHER, MT_IM_AUTH_CASE, 2, 0x99);
    CHECK(complete(S_CASE_OTHER, NULL) == MT_COMM_INVALID_AUTH);
    fx_session(S_CASE1, MT_IM_AUTH_CASE, 1, ADMIN1);
    F.commit_err = MT_ERR_IO;
    CHECK(complete(S_CASE1, &st) == -1 && st == MT_IM_FAILURE && mt_root_failsafe_armed(&F.r)); /* staged state failed */
    F.commit_err = MT_OK;
    CHECK(complete(S_CASE1, NULL) == MT_COMM_OK && F.commits == 2);
    CHECK(!mt_root_failsafe_armed(&F.r) && rd_u(GC, 0, 0) && mt_fabric_committed_count(&F.t) == 1);
    CHECK(saw(MT_ROOT_EV_COMMISSIONED, 1));
    CHECK(complete(S_CASE1, NULL) == MT_COMM_NO_FAILSAFE);
    /* reboot: the fabric with label and ACL came from storage */
    fx_init(true);
    const mt_fabric *f = mt_fabric_get(&F.t, 1);
    CHECK(f && !strcmp(f->label, "Home") && f->n_acl == 1 && f->acl[0].subjects[0] == ADMIN1 && f->vendor_id == 0xFFF1);
}

/* Apple adds a second fabric over the first fabric's CASE session (docs/matter-apple-trace.md); and Root01 again
 * (same root and fabric ID) is a conflict. Root02 / ICA02 / Node02_01 has an ICAC. */
static void test_second_fabric_and_conflict(void)
{
    mt_tlv_rd o, x;
    mt_span v;
    uint8_t idx = 0;
    mt_im_status st;
    fx_init(false);
    commission_first();
    F.n_ev = 0;
    /* a CASE session may not take a disarmed fail-safe while a commissioning window is open */
    F.window = true;
    CHECK(arm(S_CASE1, 60, 5) == MT_COMM_BUSY_WITH_OTHER_ADMIN && !mt_root_failsafe_armed(&F.r));
    F.window = false;
    CHECK(arm(S_CASE1, 60, 5) == MT_COMM_OK);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    CHECK(arm(S_PASE, 60, 6) == MT_COMM_BUSY_WITH_OTHER_ADMIN && rd_u(GC, 0, 5)); /* armed by fabric 1 */
    CHECK(csr(S_PASE, "Node02_01", k_Node02_01_priv, 0, &o) == MT_IM_FAILSAFE_REQUIRED);
    /* Root01 again: FabricConflict */
    CHECK(csr(S_CASE1, "Node01_01", k_Node01_01_priv, 0, &o) == MT_IM_SUCCESS);
    CHECK(add_trc(S_CASE1, "Root01") == MT_IM_SUCCESS);
    CHECK(list_len(S_CASE1, false, OC, 4) == 2); /* fabric 1's root + the staged one */
    CHECK(add_noc(S_CASE1, "Node01_01", "ICA01", 0x2233, NULL) == MT_NOC_FABRIC_CONFLICT);
    CHECK(arm(S_CASE1, 0, 9) == MT_COMM_OK && !mt_root_failsafe_armed(&F.r) && rd_u(GC, 0, 0));
    CHECK(saw(MT_ROOT_EV_FAILSAFE_EXPIRED, 1) && list_len(S_CASE1, false, OC, 4) == 1 && !F.t.pend.has_key);
    /* fabric 2 with an ICAC */
    CHECK(arm(S_CASE1, 60, 5) == MT_COMM_OK);
    CHECK(csr(S_CASE1, "Node02_01", k_Node02_01_priv, 0, &o) == MT_IM_SUCCESS);
    CHECK(add_trc(S_CASE1, "Root02") == MT_IM_SUCCESS);
    CHECK(add_noc(S_CASE1, "Node02_01", "ICA02", 0x2233, &idx) == MT_NOC_OK && idx == 2);
    CHECK(F.sess[S_CASE1].fabric == 1 && F.r.fs.fabric == 2); /* no adoption over CASE */
    CHECK(label(S_CASE1, "Home", NULL) == MT_NOC_OK);
    CHECK(complete(S_CASE1, NULL) == MT_COMM_INVALID_AUTH);    /* the fail-safe now belongs to fabric 2 */
    fx_session(S_CASE2, MT_IM_AUTH_CASE, 2, 0x2233);
    CHECK(label(S_CASE2, "Home", NULL) == MT_NOC_LABEL_CONFLICT); /* fabric 1's label (chip 1.3 rule) */
    CHECK(label(S_CASE2, "Home 2", NULL) == MT_NOC_OK);
    {   /* an embedded NUL would be cut off in storage: refused, the label stays */
        mt_im_status st;
        (void)label_n(S_CASE2, "Home\0 2", 7, &st);
        CHECK(st == MT_IM_CONSTRAINT_ERROR && !strcmp(mt_fabric_get(&F.t, 2)->label, "Home 2"));
    }
    /* the label is unique among all fabrics' labels (11.18.6.11), not per root; the empty label is never in use */
    CHECK(label(S_CASE1, "Home 2", NULL) == MT_NOC_LABEL_CONFLICT);
    CHECK(label(S_CASE2, "", NULL) == MT_NOC_OK && label(S_CASE1, "", NULL) == MT_NOC_OK);
    CHECK(label(S_CASE1, "Home", NULL) == MT_NOC_OK && label(S_CASE2, "Home 2", NULL) == MT_NOC_OK);
    CHECK(complete(S_CASE2, NULL) == MT_COMM_OK && mt_fabric_committed_count(&F.t) == 2);
    /* fabric filtering of Fabrics and NOCs */
    CHECK(list_len(S_CASE1, false, OC, 1) == 2 && list_len(S_CASE1, true, OC, 1) == 1 &&
          list_len(S_CASE2, true, OC, 0) == 1 && list_len(S_CASE2, false, OC, 0) == 2);
    CHECK(rd(S_CASE2, true, OC, 0, 0, &x) == MT_OK && !mt_tlv_enter(&x) && field_b(&x, 1, &v) && span_eq(v, tl("Node02_01")));
    CHECK(field_b(&x, 2, &v) && span_eq(v, tl("ICA02")));
    CHECK(rd(S_CASE2, false, OC, 0, 0, &x) == MT_OK && !mt_tlv_enter(&x)); /* fabric 1's NOC: sensitive fields hidden */
    CHECK(!has_field(&x, 1) && !has_field(&x, 2) && has_field(&x, 254));
    CHECK(rd(S_CASE2, false, OC, 1, 0, &x) == MT_OK && !mt_tlv_enter(&x) && has_field(&x, 1) && has_field(&x, 5));
    CHECK(rd_u(OC, 3, 2) && list_len(S_CASE1, false, OC, 4) == 2);
    /* a third fabric fits (3 supported), a fourth not: TableFull */
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK && csr(S_CASE1, "Node01_01", k_Node01_01_priv, 0, &o) == MT_IM_SUCCESS);
    CHECK(add_trc(S_CASE1, "Root03") == MT_IM_SUCCESS);
    CHECK(add_noc(S_CASE1, "Node01_01", "ICA01", 0x2233, NULL) == MT_NOC_INVALID_NOC); /* chain to another root */
    CHECK(arm(S_CASE1, 0, 0) == MT_COMM_OK);
    /* RemoveFabric */
    bool hi = true;
    CHECK(remove_fabric(S_CASE1, 0, &st, NULL) == -1 && st == MT_IM_INVALID_COMMAND);
    CHECK(remove_fabric(S_CASE1, 255, &st, NULL) == -1 && st == MT_IM_INVALID_COMMAND);
    CHECK(remove_fabric(S_CASE1, 9, NULL, &hi) == MT_NOC_INVALID_FABRIC_INDEX && !hi);
    F.n_ev = 0;
    CHECK(remove_fabric(S_CASE1, 2, NULL, &hi) == MT_NOC_OK && hi && saw(MT_ROOT_EV_FABRIC_REMOVED, 2));
    CHECK(mt_fabric_count(&F.t) == 1 && rd_u(OC, 3, 1) && list_len(S_CASE1, false, ACL, 0) == 1);
}

static void test_table_full(void)
{
    mt_tlv_rd o;
    uint8_t idx;
    fx_init(false);
    commission_first();
    /* fill slots 2 and 3 straight through the table (no more distinct test roots with keys) */
    for (unsigned s = 0; s < MT_FABRIC_MAX; s++)
        if (!F.t.slots[s].index) { F.t.slots[s] = F.t.slots[0]; F.t.slots[s].index = (uint8_t)(s + 10); F.t.slots[s].fabric_id = s; }
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK && csr(S_CASE1, "Node02_01", k_Node02_01_priv, 0, &o) == MT_IM_SUCCESS);
    CHECK(add_trc(S_CASE1, "Root02") == MT_IM_SUCCESS);
    CHECK(add_noc(S_CASE1, "Node02_01", "ICA02", 0x2233, &idx) == MT_NOC_TABLE_FULL);
}

static void test_update_noc(void)
{
    mt_tlv_rd o, x;
    mt_span v;
    mt_im_status st;
    mt_tlv_wr *w;
    uint32_t rc;
    fx_init(false);
    commission_first();
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl("Node01_01"));
    CHECK(invoke(S_CASE1, OC, 7, w, &rc, &o) == MT_IM_FAILSAFE_REQUIRED);
    CHECK(arm(S_CASE1, 60, 3) == MT_COMM_OK);
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl("Node01_01"));
    CHECK(invoke(S_CASE1, OC, 7, w, &rc, &o) == MT_IM_SUCCESS && code_of(0, rc, 8, &o) == MT_NOC_MISSING_CSR);
    /* CSR not for update: UpdateNOC refuses; a CSR for update: AddNOC refuses */
    CHECK(csr(S_CASE1, "Node01_01", k_Node01_01_priv, 0, &o) == MT_IM_SUCCESS);
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl("Node01_01"));
    CHECK(invoke(S_CASE1, OC, 7, w, &rc, &o) == MT_IM_CONSTRAINT_ERROR);
    CHECK(csr(S_CASE1, "Node01_01", k_Node01_01_priv, 1, &o) == MT_IM_SUCCESS);
    CHECK(add_noc_x(S_CASE1, "Node01_01", "ICA01", 16, 1, 0xFFF1, &st, NULL) == -1 && st == MT_IM_CONSTRAINT_ERROR);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl("Node01_01"));
    CHECK(invoke(S_PASE, OC, 7, w, &rc, &o) == MT_IM_UNSUPPORTED_ACCESS); /* fabric-scoped */
    /* chip order: another fabric ID -> InvalidFabricIndex (collision check; no such test cert under Root01), bad
     * chain -> InvalidNOC, then the key. The chip test certs all share one fabric ID. */
    CHECK(fabric_of("Node02_01") == fabric_of("Node01_01") && fabric_of("Node01_02") == fabric_of("Node01_01"));
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl("Node02_01")); mt_tlv_put_bytes(w, mt_tlv_ctx(1), tl("ICA02"));
    CHECK(invoke(S_CASE1, OC, 7, w, &rc, &o) == MT_IM_SUCCESS && code_of(0, rc, 8, &o) == MT_NOC_INVALID_NOC);
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl("Node01_01"));
    CHECK(invoke(S_CASE1, OC, 7, w, &rc, &o) == MT_IM_SUCCESS && code_of(0, rc, 8, &o) == MT_NOC_INVALID_NOC);
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl("Node01_02"));
    CHECK(invoke(S_CASE1, OC, 7, w, &rc, &o) == MT_IM_SUCCESS && code_of(0, rc, 8, &o) == MT_NOC_INVALID_PUBLIC_KEY);
    CHECK(!F.t.pend.kind && !F.t.pend.rcac_len && F.t.pend.has_key); /* nothing left staged by the failures */
    F.n_ev = 0;
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl("Node01_01")); mt_tlv_put_bytes(w, mt_tlv_ctx(1), tl("ICA01"));
    CHECK(invoke(S_CASE1, OC, 7, w, &rc, &o) == MT_IM_SUCCESS && code_of(0, rc, 8, &o) == MT_NOC_OK);
    CHECK(saw(MT_ROOT_EV_NOC_UPDATED, 1) && (F.r.fs.flags & MT_FS_UPDATE_NOC));
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl("Node01_01"));
    CHECK(invoke(S_CASE1, OC, 7, w, &rc, &o) == MT_IM_CONSTRAINT_ERROR); /* once per fail-safe */
    CHECK(complete(S_CASE1, NULL) == MT_COMM_OK);
    CHECK(rd(S_CASE1, true, OC, 0, 0, &x) == MT_OK && !mt_tlv_enter(&x) && field_b(&x, 1, &v) && span_eq(v, tl("Node01_01")));
    CHECK(field_b(&x, 2, &v) && span_eq(v, tl("ICA01")) && mt_fabric_get(&F.t, 1)->node_id == node_of("Node01_01"));
    /* an UpdateNOC rolled back by the fail-safe */
    CHECK(arm(S_CASE1, 60, 3) == MT_COMM_OK && csr(S_CASE1, "Node01_02", k_Node01_02_priv, 1, &o) == MT_IM_SUCCESS);
    w = req(); mt_tlv_put_bytes(w, mt_tlv_ctx(0), tl("Node01_02"));
    CHECK(invoke(S_CASE1, OC, 7, w, &rc, &o) == MT_IM_SUCCESS && code_of(0, rc, 8, &o) == MT_NOC_OK);
    CHECK(mt_fabric_get(&F.t, 1)->node_id == node_of("Node01_02"));
    F.now += 60000;
    CHECK(mt_root_poll(&F.r) == UINT32_MAX && mt_fabric_get(&F.t, 1)->node_id == node_of("Node01_01"));
}

static void test_failsafe_timer(void)
{
    mt_tlv_rd o;
    fx_init(false);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    CHECK(mt_root_poll(&F.r) == UINT32_MAX);
    CHECK(arm(S_PASE, 60, 3) == MT_COMM_OK);
    F.now += 59999;
    CHECK(mt_root_poll(&F.r) == 1 && mt_root_failsafe_armed(&F.r));
    F.now += 1;
    CHECK(mt_root_poll(&F.r) == UINT32_MAX && !mt_root_failsafe_armed(&F.r) && rd_u(GC, 0, 0));
    CHECK(saw(MT_ROOT_EV_FAILSAFE_EXPIRED, 0));
    /* re-arming never extends past first arm + 900 s */
    F.now = 0xFFFFF000u; /* and across the 32-bit wrap */
    CHECK(arm(S_PASE, 900, 1) == MT_COMM_OK);
    F.now += 800000;
    CHECK(arm(S_PASE, 300, 2) == MT_COMM_OK && mt_root_poll(&F.r) == 100000);
    F.now += 50000;
    CHECK(arm(S_PASE, 10, 2) == MT_COMM_OK && mt_root_poll(&F.r) == 10000); /* shortening is fine */
    CHECK(arm(S_PASE, 0, 77) == MT_COMM_OK && !mt_root_failsafe_armed(&F.r) && rd_u(GC, 0, 0));
    CHECK(arm(S_PASE, 0, 77) == MT_COMM_OK && rd_u(GC, 0, 0)); /* disarmed: no-op */
    /* rollback of a staged fabric on expiry: root, key, fabric, adoption is the node's job (event flags) */
    F.n_ev = 0;
    CHECK(arm(S_PASE, 60, 1) == MT_COMM_OK && csr(S_PASE, "Node01_02", k_Node01_02_priv, -1, &o) == MT_IM_SUCCESS);
    CHECK(add_trc(S_PASE, "Root01") == MT_IM_SUCCESS && add_noc(S_PASE, "Node01_02", NULL, ADMIN1, NULL) == MT_NOC_OK);
    CHECK(mt_fabric_count(&F.t) == 1);
    mt_root_failsafe_expire(&F.r);
    CHECK(mt_fabric_count(&F.t) == 0 && list_len(S_PASE, false, OC, 4) == 0 && !F.t.pend.has_key);
    CHECK(F.n_ev == 2 && F.evs[1].ev == MT_ROOT_EV_FAILSAFE_EXPIRED && F.evs[1].fabric == 1 &&
          (F.evs[1].flags & MT_FS_ADD_NOC) && (F.evs[1].flags & MT_FS_ADD_TRC));
    /* RemoveFabric of the pending fabric ends the fail-safe */
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    CHECK(arm(S_PASE, 60, 1) == MT_COMM_OK && csr(S_PASE, "Node01_02", k_Node01_02_priv, -1, &o) == MT_IM_SUCCESS);
    uint8_t idx = 0;
    CHECK(add_trc(S_PASE, "Root01") == MT_IM_SUCCESS && add_noc(S_PASE, "Node01_02", NULL, ADMIN1, &idx) == MT_NOC_OK);
    CHECK(idx == 2); /* indices are not reused right away */
    bool hi = false;
    CHECK(remove_fabric(S_PASE, idx, NULL, &hi) == MT_NOC_OK && hi && !mt_root_failsafe_armed(&F.r) && mt_fabric_count(&F.t) == 0);
    /* a CASE session of another fabric cannot disarm or re-arm someone else's fail-safe */
    fx_init(false);
    commission_first();
    fx_session(S_CASE2, MT_IM_AUTH_CASE, 2, 5);
    CHECK(arm(S_CASE1, 60, 4) == MT_COMM_OK && arm(S_CASE2, 0, 0) == MT_COMM_BUSY_WITH_OTHER_ADMIN && mt_root_failsafe_armed(&F.r));
}

/* ---- access control ---- */

static mt_acl_entry entry(uint8_t priv, unsigned ns, const uint64_t *subj_, unsigned nt, const mt_acl_target *tg)
{
    mt_acl_entry e;
    memset(&e, 0, sizeof e);
    e.privilege = priv;
    e.auth_mode = MT_ACL_AUTH_CASE;
    e.n_subjects = (uint8_t)ns;
    e.n_targets = (uint8_t)nt;
    for (unsigned i = 0; i < ns; i++) e.subjects[i] = subj_[i];
    for (unsigned i = 0; i < nt; i++) e.targets[i] = tg[i];
    return e;
}

static void test_acl_check(void)
{
    static mt_fabric_table t;
    mt_root_session s;
    memset(&t, 0, sizeof t);
    fx_init(false); /* for the node tree (device types) */
    t.slots[0].index = 1;
    t.slots[1].index = 2;
    mt_fabric *f = &t.slots[0];
    const uint64_t node = 0x1122, cat_sub = 0xFFFFFFFD00AB0002ull;
    const mt_acl_target tc = { 0x201, MT_ACL_NO_ENDPOINT, MT_ACL_NO_DEVTYPE },
                        te = { MT_ACL_NO_CLUSTER, 1, MT_ACL_NO_DEVTYPE },
                        td = { MT_ACL_NO_CLUSTER, MT_ACL_NO_ENDPOINT, 0x301 };
    memset(&s, 0, sizeof s);
    s.auth = MT_IM_AUTH_PASE;
    CHECK(mt_acl_check(&t, &F.node, &s, 0, 0x3E, MT_IM_PRIV_ADMINISTER)); /* PASE: implicit admin */
    s.auth = MT_IM_AUTH_CASE;
    s.fabric = 1;
    s.peer_node = node;
    CHECK(!mt_acl_check(&t, &F.node, &s, 0, 0x28, MT_IM_PRIV_VIEW)); /* no entries */
    /* subject by node id */
    f->n_acl = 1;
    f->acl[0] = entry(MT_ACL_PRIV_ADMINISTER, 1, &node, 0, NULL);
    CHECK(mt_acl_check(&t, &F.node, &s, 0, 0x28, MT_IM_PRIV_ADMINISTER));
    CHECK(mt_acl_check(&t, &F.node, &s, 1, 0x201, MT_IM_PRIV_PROXY_VIEW));
    s.peer_node = 0x1123;
    CHECK(!mt_acl_check(&t, &F.node, &s, 0, 0x28, MT_IM_PRIV_VIEW));
    s.fabric = 2; s.peer_node = node;
    CHECK(!mt_acl_check(&t, &F.node, &s, 0, 0x28, MT_IM_PRIV_VIEW)); /* another fabric's entry */
    s.fabric = 1;
    s.auth = MT_IM_AUTH_NONE;
    CHECK(!mt_acl_check(&t, &F.node, &s, 0, 0x28, MT_IM_PRIV_VIEW));
    s.auth = MT_IM_AUTH_CASE;
    /* privilege table (6.6.2.1) */
    static const struct { uint8_t entry, req; bool ok; } P[] = {
        { 1, 1, true }, { 1, 2, false }, { 1, 3, false },
        { 2, 1, true }, { 2, 2, true }, { 2, 3, false },
        { 3, 1, true }, { 3, 2, false }, { 3, 3, true }, { 3, 4, false },
        { 4, 1, true }, { 4, 2, false }, { 4, 3, true }, { 4, 4, true }, { 4, 5, false },
        { 5, 1, true }, { 5, 2, true }, { 5, 3, true }, { 5, 4, true }, { 5, 5, true },
    };
    for (size_t i = 0; i < sizeof P / sizeof P[0]; i++) {
        f->acl[0] = entry(P[i].entry, 0, NULL, 0, NULL);
        CHECK(mt_acl_check(&t, &F.node, &s, 0, 0x28, P[i].req) == P[i].ok);
    }
    /* CAT subject: same identifier, version >= */
    f->acl[0] = entry(MT_ACL_PRIV_OPERATE, 1, &cat_sub, 0, NULL);
    s.n_cats = 1;
    s.cats[0] = 0x00AB0002; CHECK(mt_acl_check(&t, &F.node, &s, 1, 0x201, MT_IM_PRIV_OPERATE));
    s.cats[0] = 0x00AB0003; CHECK(mt_acl_check(&t, &F.node, &s, 1, 0x201, MT_IM_PRIV_OPERATE));
    s.cats[0] = 0x00AB0001; CHECK(!mt_acl_check(&t, &F.node, &s, 1, 0x201, MT_IM_PRIV_OPERATE));
    s.cats[0] = 0x00AC0005; CHECK(!mt_acl_check(&t, &F.node, &s, 1, 0x201, MT_IM_PRIV_OPERATE));
    s.n_cats = 0;           CHECK(!mt_acl_check(&t, &F.node, &s, 1, 0x201, MT_IM_PRIV_OPERATE));
    /* targets */
    f->acl[0] = entry(MT_ACL_PRIV_OPERATE, 0, NULL, 1, &tc);
    CHECK(mt_acl_check(&t, &F.node, &s, 1, 0x201, MT_IM_PRIV_OPERATE) && !mt_acl_check(&t, &F.node, &s, 1, 0x6, MT_IM_PRIV_OPERATE));
    f->acl[0] = entry(MT_ACL_PRIV_OPERATE, 0, NULL, 1, &te);
    CHECK(mt_acl_check(&t, &F.node, &s, 1, 0x6, MT_IM_PRIV_OPERATE) && !mt_acl_check(&t, &F.node, &s, 0, 0x6, MT_IM_PRIV_OPERATE));
    f->acl[0] = entry(MT_ACL_PRIV_OPERATE, 0, NULL, 1, &td);
    CHECK(mt_acl_check(&t, &F.node, &s, 1, 0x6, MT_IM_PRIV_OPERATE) && !mt_acl_check(&t, &F.node, &s, 0, 0x6, MT_IM_PRIV_OPERATE));
    CHECK(!mt_acl_check(&t, NULL, &s, 1, 0x6, MT_IM_PRIV_OPERATE));
    mt_acl_target both[2] = { tc, te };
    f->acl[0] = entry(MT_ACL_PRIV_OPERATE, 0, NULL, 2, both); /* any target matches */
    CHECK(mt_acl_check(&t, &F.node, &s, 0, 0x201, MT_IM_PRIV_OPERATE) && mt_acl_check(&t, &F.node, &s, 1, 0x6, MT_IM_PRIV_OPERATE));
    CHECK(!mt_acl_check(&t, &F.node, &s, 0, 0x6, MT_IM_PRIV_OPERATE));
    mt_acl_target tce = { 0x201, 1, MT_ACL_NO_DEVTYPE };      /* all fields of one target must match */
    f->acl[0] = entry(MT_ACL_PRIV_OPERATE, 0, NULL, 1, &tce);
    CHECK(mt_acl_check(&t, &F.node, &s, 1, 0x201, MT_IM_PRIV_OPERATE) && !mt_acl_check(&t, &F.node, &s, 0, 0x201, MT_IM_PRIV_OPERATE));
    /* group entries never grant CASE access; a second entry can */
    f->acl[0] = entry(MT_ACL_PRIV_OPERATE, 0, NULL, 0, NULL);
    f->acl[0].auth_mode = MT_ACL_AUTH_GROUP;
    CHECK(!mt_acl_check(&t, &F.node, &s, 1, 0x6, MT_IM_PRIV_VIEW));
    f->n_acl = 2;
    f->acl[1] = entry(MT_ACL_PRIV_VIEW, 1, &node, 0, NULL);
    CHECK(mt_acl_check(&t, &F.node, &s, 1, 0x6, MT_IM_PRIV_VIEW) && !mt_acl_check(&t, &F.node, &s, 1, 0x6, MT_IM_PRIV_OPERATE));
}

/* mt_root_access through the DM, with CATs from the node's session. */
static void test_root_access(void)
{
    const uint64_t cat_sub = 0xFFFFFFFD00AB0002ull;
    fx_init(false);
    commission_first();
    mt_im_subject s = subj(S_CASE1);
    CHECK(mt_dm_im.access(&F.dm, &s, 0, 0x3E, MT_IM_PRIV_ADMINISTER));
    fx_session(S_CASE2, MT_IM_AUTH_CASE, 1, 0x7777);
    s = subj(S_CASE2);
    CHECK(!mt_dm_im.access(&F.dm, &s, 1, 0x201, MT_IM_PRIV_OPERATE));
    mt_acl_entry e[2] = { F.t.slots[0].acl[0], entry(MT_ACL_PRIV_OPERATE, 1, &cat_sub, 0, NULL) };
    CHECK(mt_fabric_acl_set(&F.t, 1, e, 2, mt_buf_of(F.scratch, sizeof F.scratch)) == MT_OK);
    CHECK(!mt_dm_im.access(&F.dm, &s, 1, 0x201, MT_IM_PRIV_OPERATE));
    F.sess[S_CASE2].n_cats = 1;
    F.sess[S_CASE2].cats[0] = 0x00AB0002;
    CHECK(mt_dm_im.access(&F.dm, &s, 1, 0x201, MT_IM_PRIV_OPERATE));
    F.have[S_CASE2] = false; /* session gone: no CATs */
    CHECK(!mt_dm_im.access(&F.dm, &s, 1, 0x201, MT_IM_PRIV_OPERATE));
    s.auth = MT_IM_AUTH_PASE;
    CHECK(mt_dm_im.access(&F.dm, &s, 0, 0x3E, MT_IM_PRIV_ADMINISTER));
}

static void put_entry(mt_tlv_wr *w, uint8_t priv, uint8_t auth, uint64_t subject, uint8_t fabric_tag)
{
    mt_tlv_start(w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_u(w, mt_tlv_ctx(1), priv);
    mt_tlv_put_u(w, mt_tlv_ctx(2), auth);
    if (subject) {
        mt_tlv_start(w, mt_tlv_ctx(3), MT_TLV_ARRAY);
        mt_tlv_put_u(w, mt_tlv_anon(), subject);
        mt_tlv_end(w);
    } else {
        mt_tlv_put_null(w, mt_tlv_ctx(3));
    }
    mt_tlv_put_null(w, mt_tlv_ctx(4));
    mt_tlv_put_u(w, mt_tlv_ctx(254), fabric_tag); /* ignored: the accessing fabric owns the entry */
    mt_tlv_end(w);
}

static void test_acl_attribute(void)
{
    static uint8_t buf[800];
    mt_tlv_wr w;
    mt_tlv_rd x;
    uint64_t u;
    mt_tlv_rd o;
    uint8_t idx;
    fx_init(false);
    commission_first();
    /* fabric 2 so filtering has something to hide */
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK && csr(S_CASE1, "Node02_01", k_Node02_01_priv, 0, &o) == MT_IM_SUCCESS);
    CHECK(add_trc(S_CASE1, "Root02") == MT_IM_SUCCESS && add_noc(S_CASE1, "Node02_01", "ICA02", 0x2233, &idx) == MT_NOC_OK);
    fx_session(S_CASE2, MT_IM_AUTH_CASE, 2, 0x2233);
    CHECK(complete(S_CASE2, NULL) == MT_COMM_OK);
    CHECK(rd_u(ACL, 2, 4) && rd_u(ACL, 3, 3) && rd_u(ACL, 4, 4));
    /* replace fabric 1's list (Apple writes the ACL once after AddNOC) */
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_ARRAY);
    put_entry(&w, MT_ACL_PRIV_ADMINISTER, MT_ACL_AUTH_CASE, ADMIN1, 7);
    put_entry(&w, MT_ACL_PRIV_VIEW, MT_ACL_AUTH_CASE, 0xFFFFFFFD00010001ull, 7);
    mt_tlv_end(&w);
    CHECK(wr(S_CASE1, ACL, 0, MT_IM_WR_VALUE, &w) == MT_IM_SUCCESS);
    CHECK(list_len(S_CASE1, true, ACL, 0) == 2 && list_len(S_CASE2, true, ACL, 0) == 1 && list_len(S_CASE1, false, ACL, 0) == 3);
    CHECK(rd(S_CASE1, true, ACL, 0, 1, &x) == MT_OK && !mt_tlv_enter(&x) && field_u(&x, 1, &u) && u == 1 &&
          field_u(&x, 254, &u) && u == 1);
    CHECK(rd(S_CASE1, false, ACL, 0, 2, &x) == MT_OK && !mt_tlv_enter(&x) && !has_field(&x, 1) && !has_field(&x, 3) &&
          field_u(&x, 254, &u) && u == 2); /* fabric 2's entry, seen by fabric 1 */
    CHECK(rd(S_CASE1, false, ACL, 0, 3, &x) == MT_ERR_NOT_FOUND);
    /* append up to the cap */
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    put_entry(&w, MT_ACL_PRIV_OPERATE, MT_ACL_AUTH_CASE, 0x4455, 0);
    CHECK(wr(S_CASE1, ACL, 0, MT_IM_WR_LIST_APPEND, &w) == MT_IM_SUCCESS);
    CHECK(wr(S_CASE1, ACL, 0, MT_IM_WR_LIST_APPEND, &w) == MT_IM_SUCCESS);
    CHECK(wr(S_CASE1, ACL, 0, MT_IM_WR_LIST_APPEND, &w) == MT_IM_RESOURCE_EXHAUSTED);
    CHECK(list_len(S_CASE1, true, ACL, 0) == 4);
    /* invalid entries: PASE auth mode, Group + Administer, bad privilege, bad subject */
    static const struct { uint8_t priv, auth; uint64_t subj; } BAD[] = {
        { 5, MT_ACL_AUTH_PASE, 0 }, { 5, MT_ACL_AUTH_GROUP, 0 }, { 6, MT_ACL_AUTH_CASE, 0 }, { 0, MT_ACL_AUTH_CASE, 0 },
        { 3, MT_ACL_AUTH_CASE, 0xFFFFFFFFFFFF0001ull },
    };
    for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
        mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_ARRAY);
        put_entry(&w, BAD[i].priv, BAD[i].auth, BAD[i].subj, 0);
        mt_tlv_end(&w);
        CHECK(wr(S_CASE1, ACL, 0, MT_IM_WR_VALUE, &w) == MT_IM_CONSTRAINT_ERROR);
    }
    CHECK(list_len(S_CASE1, true, ACL, 0) == 4); /* unchanged */
    /* more entries than the cap */
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_ARRAY);
    for (int i = 0; i < 5; i++) put_entry(&w, MT_ACL_PRIV_VIEW, MT_ACL_AUTH_CASE, 0x10 + (unsigned)i, 0);
    mt_tlv_end(&w);
    CHECK(wr(S_CASE1, ACL, 0, MT_IM_WR_VALUE, &w) == MT_IM_RESOURCE_EXHAUSTED);
    /* not an array */
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_tlv_put_u(&w, mt_tlv_anon(), 1);
    CHECK(wr(S_CASE1, ACL, 0, MT_IM_WR_VALUE, &w) == MT_IM_INVALID_DATA_TYPE);
    /* no accessing fabric (PASE before AddNOC) */
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_ARRAY);
    mt_tlv_end(&w);
    CHECK(wr(S_PASE, ACL, 0, MT_IM_WR_VALUE, &w) == MT_IM_UNSUPPORTED_ACCESS);
    CHECK(list_len(S_PASE, true, ACL, 0) == 0);
    /* an empty list from fabric 2 clears only fabric 2's entries; persisted */
    CHECK(wr(S_CASE2, ACL, 0, MT_IM_WR_VALUE, &w) == MT_IM_SUCCESS);
    fx_init(true);
    CHECK(mt_fabric_get(&F.t, 1)->n_acl == 4 && mt_fabric_get(&F.t, 2)->n_acl == 0);
}

static void test_gkm(void)
{
    mt_tlv_wr *w;
    mt_tlv_rd o, x;
    uint32_t rc;
    uint64_t u;
    mt_im_status st;
    static uint8_t buf[64];
    mt_tlv_wr aw;
    fx_init(false);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    CHECK(rd_u(GKM, 2, 0) && rd_u(GKM, 3, 1) && list_len(S_PASE, false, GKM, 0) == 0 && list_len(S_PASE, false, GKM, 1) == 0);
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), 0);
    CHECK(invoke(S_PASE, GKM, 1, w, &rc, &o) == MT_IM_UNSUPPORTED_ACCESS); /* fabric-scoped */
    commission_first();
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), 0);
    CHECK(invoke(S_CASE1, GKM, 1, w, &rc, &o) == MT_IM_SUCCESS && rc == 2);
    CHECK(!mt_tlv_find_ctx(&o, 0) && !mt_tlv_enter(&o));
    x = o; CHECK(field_u(&x, 0, &u) && u == 0 && field_u(&x, 1, &u) && u == 0 && field_u(&x, 3, &u) && u == 0);
    x = o; CHECK(!mt_tlv_find_ctx(&x, 2) && x.type == MT_TLV_NULL);  /* keys are never returned */
    x = o; CHECK(!mt_tlv_find_ctx(&x, 7) && x.type == MT_TLV_NULL);
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), 1);
    CHECK(invoke(S_CASE1, GKM, 1, w, &rc, &o) == MT_IM_NOT_FOUND);
    CHECK(invoke(S_CASE1, GKM, 4, NULL, &rc, &o) == MT_IM_SUCCESS && rc == 5);
    CHECK(!mt_tlv_find_ctx(&o, 0) && o.type == MT_TLV_ARRAY && !mt_tlv_enter(&o) && !mt_tlv_next(&o) &&
          !mt_tlv_get_u64(&o, &u) && u == 0 && mt_tlv_next(&o) == MT_ERR_NOT_FOUND);
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), 0);
    CHECK(invoke(S_CASE1, GKM, 3, w, &rc, &o) == MT_IM_INVALID_COMMAND);
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), 5);
    CHECK(invoke(S_CASE1, GKM, 3, w, &rc, &o) == MT_IM_NOT_FOUND);
    /* KeySetWrite */
#define KSW(id, keylen) (w = req(), mt_tlv_start(w, mt_tlv_ctx(0), MT_TLV_STRUCT), mt_tlv_put_u(w, mt_tlv_ctx(0), id), \
    mt_tlv_put_u(w, mt_tlv_ctx(1), 0), mt_tlv_put_bytes(w, mt_tlv_ctx(2), mt_span_of(IPK, keylen)), \
    mt_tlv_put_u(w, mt_tlv_ctx(3), 1), mt_tlv_end(w), st = invoke(S_CASE1, GKM, 0, w, &rc, &o))
    KSW(1, 16); CHECK(st == MT_IM_RESOURCE_EXHAUSTED);
    KSW(0, 16); CHECK(st == MT_IM_INVALID_COMMAND);
    KSW(1, 15); CHECK(st == MT_IM_CONSTRAINT_ERROR);
#undef KSW
    w = req();
    CHECK(invoke(S_CASE1, GKM, 0, w, &rc, &o) == MT_IM_INVALID_COMMAND);
    /* GroupKeyMap writes */
    mt_tlv_wr_init(&aw, mt_buf_of(buf, sizeof buf));
    mt_tlv_start(&aw, mt_tlv_anon(), MT_TLV_ARRAY);
    mt_tlv_end(&aw);
    CHECK(wr(S_CASE1, GKM, 0, MT_IM_WR_VALUE, &aw) == MT_IM_SUCCESS);
    mt_tlv_wr_init(&aw, mt_buf_of(buf, sizeof buf));
    mt_tlv_start(&aw, mt_tlv_anon(), MT_TLV_ARRAY);
    mt_tlv_start(&aw, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_u(&aw, mt_tlv_ctx(1), 0x0101);
    mt_tlv_put_u(&aw, mt_tlv_ctx(2), 0);
    mt_tlv_end(&aw);
    mt_tlv_end(&aw);
    CHECK(wr(S_CASE1, GKM, 0, MT_IM_WR_VALUE, &aw) == MT_IM_CONSTRAINT_ERROR);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    CHECK(wr(S_PASE, GKM, 0, MT_IM_WR_VALUE, &aw) == MT_IM_UNSUPPORTED_ACCESS);
}

static void test_init_checks(void)
{
    mt_root r;
    fx_init(false);
    mt_root_cfg cfg = F.r.c;
    CHECK(mt_root_init(&r, &cfg) == MT_OK);
    cfg.scratch.cap = MT_ROOT_SCRATCH - 1;
    CHECK(mt_root_init(&r, &cfg) == MT_ERR_INVALID);
    cfg = F.r.c; cfg.location_cap = 3;
    CHECK(mt_root_init(&r, &cfg) == MT_ERR_INVALID);
    cfg = F.r.c; cfg.creds = NULL;
    CHECK(mt_root_init(&r, &cfg) == MT_ERR_INVALID);
    mt_root_ops o = F.ops;
    o.adopt_fabric = NULL;
    cfg = F.r.c; cfg.ops = &o;
    CHECK(mt_root_init(&r, &cfg) == MT_ERR_INVALID);
    o = F.ops; o.commit = NULL; o.event = NULL; o.opkey_gen = NULL; /* optional */
    cfg.ops = &o;
    CHECK(mt_root_init(&r, &cfg) == MT_OK);
}

/* Without opkey_gen the key comes from the node's RNG; the CSR still carries the staged key. */
static void test_csr_own_key(void)
{
    mt_tlv_rd o, e;
    mt_span el = { NULL, 0 }, v;
    fx_init(false);
    F.ops.opkey_gen = NULL;
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    CHECK(arm(S_PASE, 60, 1) == MT_COMM_OK);
    CHECK(csr(S_PASE, "Node01_02", NULL, -1, &o) == MT_IM_SUCCESS && dac_signed(S_PASE, &o, &el));
    mt_tlv_rd_init(&e, el);
    CHECK(!mt_tlv_next(&e) && !mt_tlv_enter(&e) && field_b(&e, 1, &v) && F.t.pend.has_key &&
          contains(v, F.t.pend.pub, 65) && memcmp(F.t.pend.pub, pubof("Node01_02"), 65));
}

#include "test_ctl.inc"
#include "test_time.inc"

void test_comm(void)
{
    test_gencomm_attrs();
    test_regulatory();
    test_attestation();
    test_full_commissioning();
    test_second_fabric_and_conflict();
    test_table_full();
    test_update_noc();
    test_failsafe_timer();
    test_acl_check();
    test_root_access();
    test_acl_attribute();
    test_gkm();
    test_init_checks();
    test_csr_own_key();
    test_ctl();
    test_timesync();
    mt_rng_free(&g_rng);
    printf("%d expected failures\n", g_xfail);
}
