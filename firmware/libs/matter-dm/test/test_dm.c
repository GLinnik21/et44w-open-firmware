/* Host tests for matter-dm. A static three-endpoint node (root with Basic Information-like and
 * Administrator Commissioning-like clusters, a thermostat endpoint, a custom-cluster endpoint) is run
 * through the real matter-im engine: wildcard and concrete reads (also chunked), global attribute
 * lists, the Descriptor cluster, writes with data versions and dirty marking, invoke and cmd_info.
 * No external vectors: the expected values come from the fixture tables and the spec's global
 * attribute and Descriptor definitions (Matter 1.3 sections 7.13 and 9.5). */
#include <stdio.h>
#include <string.h>
#include "mt_dm.h"
#include "im_priv.h"

static int g_fail, g_checks;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CTX(n) mt_tlv_ctx(n)
#define ANON mt_tlv_anon()

#define L MT_IM_ATTR_LIST
#define W MT_IM_ATTR_WRITABLE
#define F MT_IM_ATTR_FIXED
#define V MT_IM_PRIV_VIEW
#define O MT_IM_PRIV_OPERATE
#define A MT_IM_PRIV_ADMINISTER

/* ---------------- fixture ---------------- */

enum { CL_IDENTIFY = 0x03, CL_BASIC = 0x28, CL_ADMIN = 0x3C, CL_THERMO = 0x201, CL_CUSTOM = 0xFFF1FC01 };

static uint64_t g_label_calls, g_thermo_setpoint = 2000, g_identify_time;
static uint32_t g_custom_list[5] = { 11, 22, 33, 44, 55 };
static unsigned g_custom_n = 5;
static int g_invoke_calls;

static mt_err thermo_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                          mt_tlv_tag tag)
{
    (void)rc;
    CHECK(at->ep->id == 1 && at->cl->id == CL_THERMO);
    if (attr == 0x0000) return mt_tlv_put_i(w, tag, 2150);
    if (attr == 0x0012) return mt_tlv_put_i(w, tag, (int64_t)g_thermo_setpoint);
    if (attr == 0x001B) return mt_tlv_put_u(w, tag, 4);
    (void)item;
    return MT_ERR_INVALID;
}

static mt_im_status thermo_write(const mt_dm_at *at, const mt_im_wctx *wc, uint32_t attr, mt_im_wr_op op,
                                 mt_tlv_rd *val)
{
    (void)at; (void)wc;
    int64_t v;
    if (attr != 0x0012 || op != MT_IM_WR_VALUE) return MT_IM_UNSUPPORTED_WRITE;
    if (mt_tlv_get_i64(val, &v)) return MT_IM_INVALID_DATA_TYPE;
    if (v < 500 || v > 4000) return MT_IM_CONSTRAINT_ERROR;
    g_thermo_setpoint = (uint64_t)v;
    return MT_IM_SUCCESS;
}

static mt_im_status thermo_invoke(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                                  mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    (void)s;
    g_invoke_calls++;
    CHECK(cmd == 0 && fields->type == MT_TLV_STRUCT);
    mt_dm_changed(at->dm, at->ep->id, at->cl->id, 0x0012);
    mt_tlv_put_u(resp, CTX(0), 7);
    *resp_cmd = 0;
    return MT_IM_SUCCESS;
}

static const mt_dm_ops k_thermo_ops = { thermo_read, thermo_write, thermo_invoke };
static const mt_dm_attr_def k_thermo_attrs[] = { { 0x0000, 0, V, 0 }, { 0x0012, W, V, O }, { 0x001B, F, V, 0 } };
static const mt_dm_cmd_def k_thermo_cmds[] = { { 0x00, O, false } };
static const uint32_t k_thermo_gen[] = { 0x00 };
static const mt_dm_cluster k_thermo = { .id = CL_THERMO, .features = 1, .revision = 6, .n_attrs = 3, .n_cmds = 1,
    .n_generated = 1, .attrs = k_thermo_attrs, .cmds = k_thermo_cmds, .generated = k_thermo_gen, .ops = &k_thermo_ops };

static mt_err ident_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                         mt_tlv_tag tag)
{
    (void)at; (void)rc; (void)item;
    return attr == 0 ? mt_tlv_put_u(w, tag, g_identify_time) : MT_ERR_INVALID;
}
static const mt_dm_ops k_ident_ops = { ident_read, 0, 0 };
static const mt_dm_attr_def k_ident_attrs[] = { { 0x0000, W, V, O } };
static const mt_dm_cmd_def k_ident_cmds[] = { { 0x00, O, false }, { 0x40, A, true } };
static const mt_dm_cluster k_ident = { .id = CL_IDENTIFY, .revision = 4, .n_attrs = 1, .n_cmds = 2,
    .attrs = k_ident_attrs, .cmds = k_ident_cmds, .ops = &k_ident_ops };

static mt_err basic_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                         mt_tlv_tag tag)
{
    (void)at; (void)rc; (void)item;
    g_label_calls++;
    return attr == 0x0002 ? mt_tlv_put_u(w, tag, 0xFFF1) : mt_tlv_put_utf8(w, tag, "lab", 3);
}
static const mt_dm_ops k_basic_ops = { basic_read, 0, 0 };
static const mt_dm_attr_def k_basic_attrs[] = { { 0x0002, F, V, 0 }, { 0x0005, W, V, MT_IM_PRIV_MANAGE } };
static const uint32_t k_basic_events[] = { 0x00 };
static const mt_dm_cluster k_basic = { .id = CL_BASIC, .revision = 3, .n_attrs = 2, .n_events = 1,
    .attrs = k_basic_attrs, .events = k_basic_events, .ops = &k_basic_ops };

static const mt_dm_attr_def k_admin_attrs[] = { { 0x0000, 0, V, 0 } };
static const mt_dm_cmd_def k_admin_cmds[] = { { 0x00, A, true }, { 0x01, A, true }, { 0x02, A, false } };
static const mt_dm_cluster k_admin = { .id = CL_ADMIN, .revision = 1, .features = 1, .n_attrs = 1, .n_cmds = 3,
    .attrs = k_admin_attrs, .cmds = k_admin_cmds };   /* no handler: globals only are readable */

static mt_err custom_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                          mt_tlv_tag tag)
{
    (void)at; (void)rc;
    if (attr == 0x00010001) return mt_tlv_put_u(w, tag, 9);
    CHECK(attr == 0x0000);
    return item < g_custom_n ? mt_tlv_put_u(w, tag, g_custom_list[item]) : MT_ERR_NOT_FOUND;
}
static const mt_dm_ops k_custom_ops = { custom_read, 0, 0 };
static const mt_dm_attr_def k_custom_attrs[] = { { 0x0000, L, V, 0 }, { 0x00010001, 0, V, 0 } };
static const mt_dm_cluster k_custom = { .id = CL_CUSTOM, .revision = 1, .n_attrs = 2, .attrs = k_custom_attrs,
    .ops = &k_custom_ops };

static const mt_dm_devtype k_root_types[] = { { 0x16, 1 } };
static const mt_dm_devtype k_thermo_types[] = { { 0x301, 2 }, { 0xFFF10001, 1 } };
static const mt_dm_devtype k_custom_types[] = { { 0xFFF10002, 3 } };
static const uint32_t k_clients[] = { 0x03, 0x1D };
static const mt_dm_cluster *const k_root_cl[] = { &mt_dm_descriptor, &k_basic, &k_admin };
static const mt_dm_cluster *const k_ep1_cl[] = { &k_ident, &mt_dm_descriptor, &k_thermo };
static const mt_dm_cluster *const k_ep2_cl[] = { &mt_dm_descriptor, &k_custom };
static const mt_dm_endpoint k_eps[] = {
    { .id = 0, .n_types = 1, .n_clusters = 3, .types = k_root_types, .clusters = k_root_cl },
    { .id = 1, .n_types = 2, .n_clusters = 3, .n_clients = 2, .types = k_thermo_types, .clusters = k_ep1_cl,
      .clients = k_clients },
    { .id = 2, .n_types = 1, .n_clusters = 2, .types = k_custom_types, .clusters = k_ep2_cl },
};
static const mt_dm_node k_node = { k_eps, 3 };
/* Attributes per cluster: own + 5 globals (+ EventList). */
#define N_ATTRS_TOTAL ((4 + 5) + (2 + 6) + (1 + 5) /* ep0 */ + (1 + 5) + (4 + 5) + (3 + 5) /* ep1 */ + \
                       (4 + 5) + (2 + 5) /* ep2 */)

/* ---------------- fake exchange layer ---------------- */

typedef struct { uint16_t exch; uint8_t op; bool expect; size_t len; uint8_t p[1400]; } sent_t;
static sent_t g_sent[64];
static int g_nsent;
static uint32_t g_now;
static uint8_t g_acl_deny_cluster_set;   /* deny reads of CL_ADMIN when set */
static uint8_t g_tx[1400];
static mt_im g_im;
static mt_dm g_dm;

static mt_err f_send(void *ctx, uint16_t session, uint16_t *exch, uint8_t op, mt_span p, bool expect)
{
    (void)ctx; (void)session;
    if (*exch == MT_IM_NEW_EXCH) *exch = 900;
    sent_t *s = &g_sent[g_nsent++ % 64];
    s->exch = *exch; s->op = op; s->expect = expect; s->len = p.len;
    memcpy(s->p, p.p, p.len);
    return MT_OK;
}
static uint32_t f_now(void *ctx) { (void)ctx; return g_now; }
static const mt_im_ports k_ports = { f_send, f_now, NULL };

static bool f_access(void *ctx, const mt_im_subject *s, uint16_t ep, uint32_t cl, uint8_t priv)
{
    (void)ctx; (void)s; (void)ep; (void)priv;
    return !(g_acl_deny_cluster_set && cl == CL_ADMIN);
}

static void reset(size_t tx_cap)
{
    mt_dm_cfg dc = { &k_node, &g_im, f_access, NULL, 0x1000 };
    g_nsent = 0; g_now = 1000; g_acl_deny_cluster_set = 0;
    g_thermo_setpoint = 2000; g_identify_time = 0; g_invoke_calls = 0; g_custom_n = 5;
    CHECK(mt_dm_init(&g_dm, &dc) == MT_OK);
    mt_im_cfg ic = { &mt_dm_im, &g_dm, &k_ports, NULL, mt_buf_of(g_tx, tx_cap), 1, 1 };
    mt_im_init(&g_im, &ic);
}

static const mt_im_subject k_subj = { 1, MT_IM_AUTH_CASE, 1, 0x1111 };

/* ---------------- request building and report collection ---------------- */

static uint8_t g_reqbuf[256];

static mt_span read_req(int n, const uint32_t (*paths)[3], const uint16_t *flags)
{
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, mt_buf_of(g_reqbuf, sizeof g_reqbuf));
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_start(&w, CTX(0), MT_TLV_ARRAY);
    for (int i = 0; i < n; i++) {
        mt_tlv_start(&w, ANON, MT_TLV_LIST);
        if (paths[i][0] != MT_IM_WILD_EP) mt_tlv_put_u(&w, CTX(2), paths[i][0]);
        if (paths[i][1] != MT_IM_WILD_ID) mt_tlv_put_u(&w, CTX(3), paths[i][1]);
        if (paths[i][2] != MT_IM_WILD_ID) mt_tlv_put_u(&w, CTX(4), paths[i][2]);
        if (flags && flags[i]) mt_tlv_put_u(&w, CTX(6), flags[i]);
        mt_tlv_end(&w);
    }
    mt_tlv_end(&w);
    mt_tlv_put_bool(&w, CTX(3), false);
    mt_tlv_put_u(&w, CTX(255), MT_IM_REVISION);
    mt_tlv_end(&w);
    return mt_tlv_wr_span(&w);
}

typedef struct {
    uint16_t ep;
    uint32_t cl, at;
    bool status, list;
    uint8_t st;
    unsigned n;              /* list items */
    uint64_t item[16];       /* list items; a struct item is (member0 << 16) | member1 */
    uint64_t val;            /* scalar */
} rec_t;
static rec_t g_rec[96];
static unsigned g_nrec;

static rec_t *rec_for(uint16_t ep, uint32_t cl, uint32_t at)
{
    for (unsigned i = 0; i < g_nrec; i++)
        if (g_rec[i].ep == ep && g_rec[i].cl == cl && g_rec[i].at == at) return &g_rec[i];
    return NULL;
}

static uint64_t elem_val(const mt_tlv_rd *r)
{
    if (!mt_tlv_is_container(r)) return r->val;
    mt_tlv_rd c = *r;
    uint64_t a = 0, b = 0;
    mt_tlv_enter(&c);
    while (!mt_tlv_next(&c)) (c.tag.num == 0 ? &a : &b)[0] = c.val;
    return a << 16 | b;
}

static void collect_chunk(const sent_t *s)
{
    mt_tlv_rd r;
    mt_tlv_rd_init(&r, mt_span_of(s->p, s->len));
    mt_tlv_next(&r); mt_tlv_enter(&r);
    if (mt_tlv_find_ctx(&r, 1)) return;
    mt_tlv_enter(&r);
    while (!mt_tlv_next(&r)) {
        mt_tlv_rd rep = r;
        mt_tlv_enter(&rep);
        mt_tlv_next(&rep);
        bool st = mt_tlv_is_ctx(&rep, 0);
        mt_tlv_enter(&rep);
        rec_t t; memset(&t, 0, sizeof t);
        bool item = false;
        uint8_t stc = 0;
        mt_tlv_rd d = {0};
        while (!mt_tlv_next(&rep)) {
            if (rep.tag.num == 1 && !st) {   /* data: path */
                mt_tlv_rd p = rep; mt_tlv_enter(&p);
                while (!mt_tlv_next(&p)) {
                    if (p.tag.num == 2) t.ep = (uint16_t)p.val;
                    if (p.tag.num == 3) t.cl = (uint32_t)p.val;
                    if (p.tag.num == 4) t.at = (uint32_t)p.val;
                    if (p.tag.num == 5) item = true;
                }
            } else if (rep.tag.num == 0 && st) {
                mt_tlv_rd p = rep; mt_tlv_enter(&p);
                while (!mt_tlv_next(&p)) {
                    if (p.tag.num == 2) t.ep = (uint16_t)p.val;
                    if (p.tag.num == 3) t.cl = (uint32_t)p.val;
                    if (p.tag.num == 4) t.at = (uint32_t)p.val;
                }
            } else if (rep.tag.num == 1 && st) {
                mt_tlv_rd p = rep; mt_tlv_enter(&p);
                while (!mt_tlv_next(&p)) if (p.tag.num == 0) stc = (uint8_t)p.val;
            } else if (rep.tag.num == 2) d = rep;
        }
        rec_t *dst = rec_for(t.ep, t.cl, t.at);
        if (!dst) { dst = &g_rec[g_nrec++]; *dst = t; }
        if (st) { dst->status = true; dst->st = stc; continue; }
        if (item) {
            dst->list = true;
            if (dst->n < 16) dst->item[dst->n++] = elem_val(&d);
        } else if (d.type == MT_TLV_ARRAY) {
            dst->list = true;
            mt_tlv_rd c = d; mt_tlv_enter(&c);
            while (!mt_tlv_next(&c)) if (dst->n < 16) dst->item[dst->n++] = elem_val(&c);
        } else {
            dst->val = d.val;
        }
    }
}

static int run_read(mt_span req)
{
    int chunks = 0;
    g_nrec = 0; g_nsent = 0;
    mt_im_on_msg(&g_im, &k_subj, 5, MT_IM_OP_READ, req);
    while (g_nsent > chunks && g_sent[chunks].op == MT_IM_OP_REPORT) {
        collect_chunk(&g_sent[chunks]);
        chunks++;
        if (!g_sent[chunks - 1].expect) break;
        const uint8_t ack[] = { 0x15, 0x24, 0x00, 0x00, 0x24, 0xFF, 0x0B, 0x18 };
        mt_im_on_msg(&g_im, &k_subj, 5, MT_IM_OP_STATUS, mt_span_of(ack, sizeof ack));
    }
    return chunks;
}

static const uint32_t WILD3[1][3] = { { MT_IM_WILD_EP, MT_IM_WILD_ID, MT_IM_WILD_ID } };

/* ---------------- tests ---------------- */

static void test_tables(void)
{
    CHECK(mt_dm_check(&k_node) == MT_OK);
    /* enumeration: count, order, indexes, flags */
    mt_im_attr a;
    unsigned n = 0;
    while (!mt_dm_im.attr_at(&g_dm, (uint16_t)n, &a)) n++;
    CHECK(n == N_ATTRS_TOTAL);
    CHECK(mt_dm_im.attr_at(&g_dm, (uint16_t)n, &a) == MT_ERR_NOT_FOUND);
    CHECK(mt_dm_im.attr_at(&g_dm, 0xFFFF, &a) == MT_ERR_NOT_FOUND);

    CHECK(!mt_dm_im.attr_at(&g_dm, 0, &a));      /* first: Descriptor DeviceTypeList on endpoint 0 */
    CHECK(a.endpoint == 0 && a.cluster == 0x1D && a.attr == 0 && a.cluster_idx == 0);
    CHECK((a.flags & (MT_IM_ATTR_LIST | MT_IM_ATTR_FIXED)) == (MT_IM_ATTR_LIST | MT_IM_ATTR_FIXED));
    CHECK(a.read_priv == V && a.write_priv == 0 && a.dataver == 0x1000);
    CHECK(!mt_dm_im.attr_at(&g_dm, 4, &a));      /* then the cluster's globals, ascending */
    CHECK(a.cluster == 0x1D && a.attr == 0xFFF8 && (a.flags & MT_IM_ATTR_LIST));
    CHECK(!mt_dm_im.attr_at(&g_dm, 5, &a) && a.attr == 0xFFF9);
    CHECK(!mt_dm_im.attr_at(&g_dm, 6, &a) && a.attr == 0xFFFB);   /* no EventList: Descriptor has no events */
    CHECK(!mt_dm_im.attr_at(&g_dm, 7, &a) && a.attr == 0xFFFC && !(a.flags & MT_IM_ATTR_LIST));
    CHECK(!mt_dm_im.attr_at(&g_dm, 8, &a) && a.attr == 0xFFFD && (a.flags & MT_IM_ATTR_FIXED));
    CHECK(!mt_dm_im.attr_at(&g_dm, 9, &a) && a.cluster == CL_BASIC && a.attr == 0x0002 && a.cluster_idx == 1);
    CHECK(!mt_dm_im.attr_at(&g_dm, 10, &a) && a.attr == 0x0005 && (a.flags & W) && a.write_priv == MT_IM_PRIV_MANAGE);
    CHECK(!mt_dm_im.attr_at(&g_dm, 13, &a) && a.attr == 0xFFFA);  /* Basic declares an event */

    /* endpoint/cluster order and dense indexes over the whole node */
    uint8_t last_idx = 0;
    uint16_t last_ep = 0;
    for (unsigned i = 0; i < n; i++) {
        mt_dm_im.attr_at(&g_dm, (uint16_t)i, &a);
        CHECK(a.cluster_idx == last_idx || a.cluster_idx == last_idx + 1);
        CHECK(a.endpoint >= last_ep);
        last_idx = a.cluster_idx; last_ep = a.endpoint;
    }
    CHECK(last_idx == 7 && last_ep == 2);   /* 8 cluster instances */
}

static void test_check_rules(void)
{
    /* each rule in mt_dm_check */
    static const mt_dm_cluster *const dup_cl[] = { &mt_dm_descriptor, &k_ident, &k_ident };
    static mt_dm_endpoint e1[1];
    mt_dm_node n = { e1, 1 };
    e1[0] = (mt_dm_endpoint){ .id = 0, .n_clusters = 3, .clusters = dup_cl };
    CHECK(mt_dm_check(&n) == MT_ERR_INVALID);                 /* cluster twice */
    static const mt_dm_cluster *const nodesc[] = { &k_ident };
    e1[0] = (mt_dm_endpoint){ .id = 0, .n_clusters = 1, .clusters = nodesc };
    CHECK(mt_dm_check(&n) == MT_ERR_INVALID);                 /* no Descriptor */
    static const mt_dm_cluster fake_desc = { .id = MT_DM_CLUSTER_DESCRIPTOR };
    static const mt_dm_cluster *const fakedesc[] = { &fake_desc };
    e1[0] = (mt_dm_endpoint){ .id = 0, .n_clusters = 1, .clusters = fakedesc };
    CHECK(mt_dm_check(&n) == MT_ERR_INVALID);                 /* a lookalike is not the Descriptor */
    static const mt_dm_cluster *const okcl[] = { &mt_dm_descriptor };
    e1[0] = (mt_dm_endpoint){ .id = 1, .n_clusters = 1, .clusters = okcl };
    CHECK(mt_dm_check(&n) == MT_ERR_INVALID);                 /* first endpoint is not 0 */
    n.n_eps = 0;
    CHECK(mt_dm_check(&n) == MT_ERR_INVALID);
    static mt_dm_endpoint e2[2];
    mt_dm_node n2 = { e2, 2 };
    e2[0] = (mt_dm_endpoint){ .id = 0, .n_clusters = 1, .clusters = okcl };
    e2[1] = e2[0];
    CHECK(mt_dm_check(&n2) == MT_ERR_INVALID);                /* endpoint id twice */
    e2[1].id = 1;
    CHECK(mt_dm_check(&n2) == MT_OK);
    static const mt_dm_attr_def bad_a[] = { { 0xFFFB, 0, V, 0 } };
    static const mt_dm_cluster bad_g = { .id = 0x99, .n_attrs = 1, .attrs = bad_a };
    static const mt_dm_cluster *const gcl[] = { &mt_dm_descriptor, &bad_g };
    e2[1].n_clusters = 2; e2[1].clusters = gcl;
    CHECK(mt_dm_check(&n2) == MT_ERR_INVALID);                /* own attribute inside the global range */
    static const mt_dm_attr_def dup_a[] = { { 1, 0, V, 0 }, { 1, 0, V, 0 } };
    static const mt_dm_cluster bad_d = { .id = 0x99, .n_attrs = 2, .attrs = dup_a };
    static const mt_dm_cluster *const dcl[] = { &mt_dm_descriptor, &bad_d };
    e2[1].clusters = dcl;
    CHECK(mt_dm_check(&n2) == MT_ERR_INVALID);                /* attribute twice */
    static const mt_dm_cmd_def dup_c[] = { { 1, 1, false }, { 1, 1, false } };
    static const mt_dm_cluster bad_c = { .id = 0x99, .n_cmds = 2, .cmds = dup_c };
    static const mt_dm_cluster *const ccl[] = { &mt_dm_descriptor, &bad_c };
    e2[1].clusters = ccl;
    CHECK(mt_dm_check(&n2) == MT_ERR_INVALID);                /* command twice */
    /* too many cluster instances: 33 */
    static mt_dm_endpoint e33[3];
    static const mt_dm_cluster *many[11];
    static mt_dm_cluster many_c[10];
    many[0] = &mt_dm_descriptor;
    for (unsigned i = 0; i < 10; i++) { many_c[i].id = 0x100 + i; many[i + 1] = &many_c[i]; }
    for (unsigned i = 0; i < 3; i++) e33[i] = (mt_dm_endpoint){ .id = (uint16_t)i, .n_clusters = 11, .clusters = many };
    mt_dm_node n3 = { e33, 3 };
    CHECK(mt_dm_check(&n3) == MT_ERR_INVALID);                /* 33 > 32 */
    n3.n_eps = 2;
    CHECK(mt_dm_check(&n3) == MT_OK);
    mt_dm d; mt_dm_cfg c = { &n3, NULL, NULL, NULL, 0 };
    CHECK(mt_dm_init(&d, &c) == MT_OK);
    n3.n_eps = 3;
    CHECK(mt_dm_init(&d, &c) == MT_ERR_INVALID);
}

static void test_wildcard_read(size_t cap)
{
    reset(cap);
    int chunks = run_read(read_req(1, WILD3, NULL));
    CHECK(chunks >= 1);
    if (cap < 1000) CHECK(chunks > 1);
    CHECK(g_nrec == N_ATTRS_TOTAL);
    for (unsigned i = 0; i < g_nrec; i++)   /* only the handler-less cluster's own attribute fails */
        CHECK(g_rec[i].status == (g_rec[i].cl == CL_ADMIN && g_rec[i].at == 0));

    /* Descriptor on endpoint 0 */
    rec_t *r = rec_for(0, 0x1D, 0);
    CHECK(r && r->list && r->n == 1 && r->item[0] == (0x16u << 16 | 1));
    r = rec_for(0, 0x1D, 1);
    CHECK(r && r->n == 3 && r->item[0] == 0x1D && r->item[1] == CL_BASIC && r->item[2] == CL_ADMIN);
    r = rec_for(0, 0x1D, 2);
    CHECK(r && r->list && r->n == 0);
    r = rec_for(0, 0x1D, 3);
    CHECK(r && r->n == 2 && r->item[0] == 1 && r->item[1] == 2);   /* flat parts */
    /* endpoint 1 */
    r = rec_for(1, 0x1D, 0);
    CHECK(r && r->n == 2 && r->item[0] == (0x301u << 16 | 2) && r->item[1] == (0xFFF10001ull << 16 | 1));
    r = rec_for(1, 0x1D, 1);
    CHECK(r && r->n == 3 && r->item[0] == 0x03 && r->item[1] == 0x1D && r->item[2] == CL_THERMO);
    r = rec_for(1, 0x1D, 2);
    CHECK(r && r->n == 2 && r->item[0] == 0x03 && r->item[1] == 0x1D);
    r = rec_for(1, 0x1D, 3);
    CHECK(r && r->list && r->n == 0);                              /* non-root: no parts */
    r = rec_for(2, 0x1D, 3);
    CHECK(r && r->list && r->n == 0);
    r = rec_for(2, 0x1D, 1);
    CHECK(r && r->n == 2 && r->item[1] == CL_CUSTOM);

    /* handler-served values, scalar and list */
    r = rec_for(1, CL_THERMO, 0x0000);
    CHECK(r && !r->list && r->val == 2150);
    r = rec_for(1, CL_THERMO, 0x0012);
    CHECK(r && r->val == 2000);
    r = rec_for(2, CL_CUSTOM, 0x0000);
    CHECK(r && r->list && r->n == 5 && r->item[0] == 11 && r->item[4] == 55);

    /* global attributes */
    r = rec_for(1, CL_THERMO, 0xFFFD); CHECK(r && r->val == 6);
    r = rec_for(1, CL_THERMO, 0xFFFC); CHECK(r && r->val == 1);
    r = rec_for(1, CL_IDENTIFY, 0xFFFC); CHECK(r && r->val == 0);
    r = rec_for(1, CL_THERMO, 0xFFFB);
    CHECK(r && r->n == 8 && r->item[0] == 0 && r->item[1] == 0x12 && r->item[2] == 0x1B && r->item[3] == 0xFFF8 &&
          r->item[4] == 0xFFF9 && r->item[5] == 0xFFFB && r->item[6] == 0xFFFC && r->item[7] == 0xFFFD);
    r = rec_for(1, CL_THERMO, 0xFFF9); CHECK(r && r->n == 1 && r->item[0] == 0);
    r = rec_for(1, CL_THERMO, 0xFFF8); CHECK(r && r->n == 1 && r->item[0] == 0);
    r = rec_for(1, CL_THERMO, 0xFFFA); CHECK(!r);                  /* no events: no EventList attribute */
    r = rec_for(1, CL_IDENTIFY, 0xFFF9); CHECK(r && r->n == 2 && r->item[0] == 0 && r->item[1] == 0x40);
    r = rec_for(1, CL_IDENTIFY, 0xFFF8); CHECK(r && r->list && r->n == 0);
    r = rec_for(0, CL_ADMIN, 0xFFF9); CHECK(r && r->n == 3 && r->item[2] == 2);
    r = rec_for(0, CL_BASIC, 0xFFFA); CHECK(r && r->n == 1 && r->item[0] == 0);
    r = rec_for(0, CL_BASIC, 0xFFFB);
    CHECK(r && r->n == 8 && r->item[0] == 2 && r->item[1] == 5 && r->item[2] == 0xFFF8 && r->item[3] == 0xFFF9 &&
          r->item[4] == 0xFFFA && r->item[5] == 0xFFFB && r->item[7] == 0xFFFD);
    r = rec_for(2, CL_CUSTOM, 0xFFFB);
    CHECK(r && r->n == 7 && r->item[0] == 0 && r->item[1] == 0x00010001);
}

static void test_handlerless(void)
{
    /* a cluster without a handler answers its own attributes with FAILURE and still serves globals */
    reset(1000);
    static const uint32_t p[2][3] = { { 0, CL_ADMIN, 0x0000 }, { 0, CL_ADMIN, 0xFFFD } };
    run_read(read_req(2, p, NULL));
    rec_t *r = rec_for(0, CL_ADMIN, 0x0000);
    CHECK(r && r->status && r->st == MT_IM_FAILURE);
    r = rec_for(0, CL_ADMIN, 0xFFFD);
    CHECK(r && !r->status && r->val == 1);
}

static void test_concrete_errors(void)
{
    reset(1000);
    static const uint32_t p[4][3] = {
        { 9, CL_THERMO, 0x0012 },       /* endpoint */
        { 1, 0x9999, 0x0012 },          /* cluster */
        { 1, CL_THERMO, 0x0099 },       /* attribute */
        { 1, CL_THERMO, 0xFFFA },       /* EventList on a cluster without events */
    };
    run_read(read_req(4, p, NULL));
    CHECK(rec_for(9, CL_THERMO, 0x12)->st == MT_IM_UNSUPPORTED_ENDPOINT);
    CHECK(rec_for(1, 0x9999, 0x12)->st == MT_IM_UNSUPPORTED_CLUSTER);
    CHECK(rec_for(1, CL_THERMO, 0x99)->st == MT_IM_UNSUPPORTED_ATTRIBUTE);
    CHECK(rec_for(1, CL_THERMO, 0xFFFA)->st == MT_IM_UNSUPPORTED_ATTRIBUTE);
}

static void test_wildcard_shapes(void)
{
    reset(1000);
    /* all endpoints, one cluster: Descriptor everywhere */
    static const uint32_t desc[1][3] = { { MT_IM_WILD_EP, 0x1D, 0 } };
    run_read(read_req(1, desc, NULL));
    CHECK(g_nrec == 3 && rec_for(0, 0x1D, 0) && rec_for(1, 0x1D, 0) && rec_for(2, 0x1D, 0));
    /* one endpoint, all clusters, one attribute id (ClusterRevision) */
    static const uint32_t rev[1][3] = { { 1, MT_IM_WILD_ID, 0xFFFD } };
    run_read(read_req(1, rev, NULL));
    CHECK(g_nrec == 3 && rec_for(1, CL_IDENTIFY, 0xFFFD)->val == 4 && rec_for(1, 0x1D, 0xFFFD)->val == 2 &&
          rec_for(1, CL_THERMO, 0xFFFD)->val == 6);
    /* the whole of one cluster */
    static const uint32_t cl[1][3] = { { 1, CL_THERMO, MT_IM_WILD_ID } };
    run_read(read_req(1, cl, NULL));
    CHECK(g_nrec == 3 + 5);
    /* flags */
    uint16_t f = MT_IM_WF_SKIP_GLOBAL;
    run_read(read_req(1, WILD3, &f));
    CHECK(g_nrec == 4 + 2 + 1 + 1 + 4 + 3 + 4 + 2);          /* own attributes only */
    CHECK(!rec_for(1, CL_THERMO, 0xFFFD));
    f = MT_IM_WF_SKIP_ROOT;
    run_read(read_req(1, WILD3, &f));
    CHECK(!rec_for(0, 0x1D, 0) && rec_for(1, 0x1D, 0));
    f = MT_IM_WF_SKIP_ATTR_LIST;
    run_read(read_req(1, WILD3, &f));
    CHECK(g_nrec == N_ATTRS_TOTAL - 8 && !rec_for(2, CL_CUSTOM, 0xFFFB));
    f = MT_IM_WF_SKIP_CMD_LISTS;
    run_read(read_req(1, WILD3, &f));
    CHECK(g_nrec == N_ATTRS_TOTAL - 16 && !rec_for(1, CL_THERMO, 0xFFF9) && rec_for(1, CL_THERMO, 0xFFFB));
    f = MT_IM_WF_SKIP_CUSTOM;
    run_read(read_req(1, WILD3, &f));
    CHECK(!rec_for(2, CL_CUSTOM, 0x0000) && !rec_for(2, CL_CUSTOM, 0xFFFD) && rec_for(1, CL_THERMO, 0x0012) &&
          !rec_for(2, CL_CUSTOM, 0x00010001));
    f = MT_IM_WF_SKIP_FIXED;
    run_read(read_req(1, WILD3, &f));
    CHECK(!rec_for(1, CL_THERMO, 0xFFFD) && !rec_for(1, CL_THERMO, 0x001B) && rec_for(1, CL_THERMO, 0x0012) &&
          !rec_for(0, 0x1D, 1) && rec_for(0, 0x1D, 3));
    /* access: wildcard skips what the ACL denies, a concrete path reports UNSUPPORTED_ACCESS */
    g_acl_deny_cluster_set = 1;
    run_read(read_req(1, WILD3, NULL));
    CHECK(!rec_for(0, CL_ADMIN, 0xFFFD) && g_nrec == N_ATTRS_TOTAL - 6);
    static const uint32_t c[1][3] = { { 0, CL_ADMIN, 0xFFFD } };
    run_read(read_req(1, c, NULL));
    CHECK(g_nrec == 1 && g_rec[0].status && g_rec[0].st == MT_IM_UNSUPPORTED_ACCESS);
}

static void test_data_versions(void)
{
    reset(1000);
    uint32_t v0, v1, vo;
    CHECK(mt_dm_dataver(&g_dm, 0, 0x1D, &v0) && v0 == 0x1000);
    CHECK(mt_dm_dataver(&g_dm, 1, CL_THERMO, &v1) && v1 == 0x1000 + 5);   /* 6th instance: ep0 has 3, ep1 idx 2 */
    CHECK(mt_dm_dataver(&g_dm, 2, CL_CUSTOM, &vo) && vo == 0x1000 + 7);
    CHECK(!mt_dm_dataver(&g_dm, 2, CL_THERMO, &vo) && !mt_dm_dataver(&g_dm, 5, 0x1D, &vo));
    mt_im_attr a;
    for (unsigned i = 0; !mt_dm_im.attr_at(&g_dm, (uint16_t)i, &a); i++) {
        uint32_t v;
        CHECK(mt_dm_dataver(&g_dm, a.endpoint, a.cluster, &v) && v == a.dataver);
    }
    /* mt_dm_changed bumps one cluster only and marks the path dirty */
    mt_dm_changed(&g_dm, 1, CL_THERMO, 0x0000);
    uint32_t v1b, v0b;
    mt_dm_dataver(&g_dm, 1, CL_THERMO, &v1b);
    mt_dm_dataver(&g_dm, 0, 0x1D, &v0b);
    CHECK(v1b == v1 + 1 && v0b == v0);
    CHECK(g_im.dirty[0].path.endpoint == 1 && g_im.dirty[0].path.cluster == CL_THERMO && g_im.dirty[0].path.id == 0);
    mt_dm_changed(&g_dm, 7, CL_THERMO, 0);   /* unknown path: ignored */
    mt_dm_dataver(&g_dm, 1, CL_THERMO, &v1b);
    CHECK(v1b == v1 + 1);
}

static mt_tlv_rd g_vrd;
static uint8_t g_vbuf[16];
static mt_tlv_rd *val_i(int64_t v)
{
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, mt_buf_of(g_vbuf, sizeof g_vbuf));
    mt_tlv_put_i(&w, CTX(1), v);
    mt_tlv_rd_init(&g_vrd, mt_tlv_wr_span(&w));
    mt_tlv_next(&g_vrd);
    return &g_vrd;
}

static bool find_attr(uint16_t ep, uint32_t cl, uint32_t at, mt_im_attr *a)
{
    for (uint16_t i = 0; !mt_dm_im.attr_at(&g_dm, i, a); i++)
        if (a->endpoint == ep && a->cluster == cl && a->attr == at) return true;
    return false;
}

static void test_write(void)
{
    reset(1000);
    mt_im_wctx wc = { &k_subj, false, false };
    mt_im_attr a;
    uint32_t v0, v1;
    CHECK(find_attr(1, CL_THERMO, 0x0012, &a));
    mt_dm_dataver(&g_dm, 1, CL_THERMO, &v0);
    CHECK(mt_dm_im.write(&g_dm, &wc, &a, MT_IM_WR_VALUE, val_i(2250)) == MT_IM_SUCCESS);
    CHECK(g_thermo_setpoint == 2250);
    mt_dm_dataver(&g_dm, 1, CL_THERMO, &v1);
    CHECK(v1 == v0 + 1);
    CHECK(g_im.dirty[0].path.cluster == CL_THERMO && g_im.dirty[0].path.id == 0x0012);
    /* handler errors pass through and change nothing */
    CHECK(mt_dm_im.write(&g_dm, &wc, &a, MT_IM_WR_VALUE, val_i(99999)) == MT_IM_CONSTRAINT_ERROR);
    CHECK(g_thermo_setpoint == 2250);
    mt_dm_dataver(&g_dm, 1, CL_THERMO, &v1);
    CHECK(v1 == v0 + 1);
    /* read-only: no WRITABLE flag, or write_priv 0 (the handler is never reached) */
    CHECK(find_attr(1, CL_THERMO, 0x0012, &a));
    mt_im_attr ro = a;
    ro.write_priv = 0;
    CHECK(mt_dm_im.write(&g_dm, &wc, &ro, MT_IM_WR_VALUE, val_i(2300)) == MT_IM_UNSUPPORTED_WRITE);
    ro = a;
    ro.flags &= (uint8_t)~W;
    CHECK(mt_dm_im.write(&g_dm, &wc, &ro, MT_IM_WR_VALUE, val_i(2300)) == MT_IM_UNSUPPORTED_WRITE);
    CHECK(g_thermo_setpoint == 2250);
    /* a global, a cluster without a write handler, an unknown path */
    CHECK(find_attr(1, CL_THERMO, 0xFFFD, &a));
    CHECK(mt_dm_im.write(&g_dm, &wc, &a, MT_IM_WR_VALUE, val_i(1)) == MT_IM_UNSUPPORTED_WRITE);
    CHECK(find_attr(1, CL_IDENTIFY, 0x0000, &a));
    CHECK(mt_dm_im.write(&g_dm, &wc, &a, MT_IM_WR_VALUE, val_i(1)) == MT_IM_UNSUPPORTED_WRITE);
    mt_im_attr bogus = a;
    bogus.endpoint = 9;
    CHECK(mt_dm_im.write(&g_dm, &wc, &bogus, MT_IM_WR_VALUE, val_i(1)) == MT_IM_UNSUPPORTED_WRITE);
    /* the whole path through the engine: WriteRequest -> handler -> dirty + new data version */
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, mt_buf_of(g_reqbuf, sizeof g_reqbuf));
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_put_bool(&w, CTX(1), false);
    mt_tlv_start(&w, CTX(2), MT_TLV_ARRAY);
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_start(&w, CTX(1), MT_TLV_LIST);
    mt_tlv_put_u(&w, CTX(2), 1);
    mt_tlv_put_u(&w, CTX(3), CL_THERMO);
    mt_tlv_put_u(&w, CTX(4), 0x0012);
    mt_tlv_end(&w);
    mt_tlv_put_i(&w, CTX(2), 2300);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    mt_tlv_put_u(&w, CTX(255), MT_IM_REVISION);
    mt_tlv_end(&w);
    g_nsent = 0;
    mt_dm_dataver(&g_dm, 1, CL_THERMO, &v0);
    mt_im_on_msg(&g_im, &k_subj, 6, MT_IM_OP_WRITE, mt_tlv_wr_span(&w));
    CHECK(g_nsent == 1 && g_sent[0].op == MT_IM_OP_WRITE_RESP);
    CHECK(g_thermo_setpoint == 2300);
    mt_dm_dataver(&g_dm, 1, CL_THERMO, &v1);
    CHECK(v1 == v0 + 1);
}

static void test_invoke(void)
{
    reset(1000);
    mt_im_cmd c = { 1, CL_THERMO, 0 };
    uint8_t priv = 0;
    bool timed = true;
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_OK && priv == O && !timed);
    c = (mt_im_cmd){ 1, CL_IDENTIFY, 0x40 };
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_OK && priv == A && timed);
    c = (mt_im_cmd){ 0, CL_ADMIN, 0x01 };
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_OK && priv == A && timed);
    c = (mt_im_cmd){ 0, CL_ADMIN, 0x02 };
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_OK && !timed);
    c = (mt_im_cmd){ 0, CL_ADMIN, 0x03 };
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_ERR_NOT_FOUND);
    c = (mt_im_cmd){ 3, CL_ADMIN, 0x00 };
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_ERR_NOT_FOUND);
    c = (mt_im_cmd){ 1, CL_BASIC, 0x00 };
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_ERR_NOT_FOUND);

    /* direct invoke: handler runs, writes its response fields, bumps the version */
    uint8_t fb[8], rb[32];
    mt_tlv_wr fw, rw;
    mt_tlv_rd fr;
    mt_tlv_wr_init(&fw, mt_buf_of(fb, sizeof fb));
    mt_tlv_start(&fw, ANON, MT_TLV_STRUCT);
    mt_tlv_end(&fw);
    mt_tlv_rd_init(&fr, mt_tlv_wr_span(&fw));
    mt_tlv_next(&fr);
    mt_tlv_wr_init(&rw, mt_buf_of(rb, sizeof rb));
    uint32_t rc = MT_IM_WILD_ID, v0, v1;
    mt_dm_dataver(&g_dm, 1, CL_THERMO, &v0);
    c = (mt_im_cmd){ 1, CL_THERMO, 0 };
    CHECK(mt_dm_im.invoke(&g_dm, &k_subj, &c, &fr, &rw, &rc) == MT_IM_SUCCESS);
    CHECK(rc == 0 && g_invoke_calls == 1 && rw.len == 3);
    mt_dm_dataver(&g_dm, 1, CL_THERMO, &v1);
    CHECK(v1 == v0 + 1);
    /* a cluster without a handler or invoke member */
    c = (mt_im_cmd){ 0, CL_ADMIN, 0 };
    CHECK(mt_dm_im.invoke(&g_dm, &k_subj, &c, &fr, &rw, &rc) == MT_IM_UNSUPPORTED_COMMAND);
    c = (mt_im_cmd){ 1, CL_IDENTIFY, 0 };
    CHECK(mt_dm_im.invoke(&g_dm, &k_subj, &c, &fr, &rw, &rc) == MT_IM_UNSUPPORTED_COMMAND);
    c = (mt_im_cmd){ 8, CL_IDENTIFY, 0 };
    CHECK(mt_dm_im.invoke(&g_dm, &k_subj, &c, &fr, &rw, &rc) == MT_IM_UNSUPPORTED_COMMAND);
}

static void test_access(void)
{
    reset(1000);
    CHECK(mt_dm_im.access(&g_dm, &k_subj, 0, CL_BASIC, V));
    g_acl_deny_cluster_set = 1;
    CHECK(!mt_dm_im.access(&g_dm, &k_subj, 0, CL_ADMIN, V));
    g_dm.access = NULL;   /* no ACL port wired: deny everything */
    CHECK(!mt_dm_im.access(&g_dm, &k_subj, 0, CL_BASIC, V));
}

int main(void)
{
    reset(1000);
    test_tables();
    test_check_rules();
    test_wildcard_read(1400);
    test_wildcard_read(200);
    test_wildcard_read(128);
    test_handlerless();
    test_concrete_errors();
    test_wildcard_shapes();
    test_data_versions();
    test_write();
    test_invoke();
    test_access();
    printf("%d checks, %d failures\n", g_checks, g_fail);
    return g_fail != 0;
}
