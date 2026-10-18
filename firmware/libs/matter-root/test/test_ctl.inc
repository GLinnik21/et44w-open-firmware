/* Tests of the endpoint-0 control clusters, included into test_comm.c (they share its fixture): Network Commissioning
 * (0x31), General Diagnostics (0x33) and Administrator Commissioning (0x3C), each against a fake port.
 * Synchronous commands go through mt_dm_im.invoke directly; ConnectNetwork/ScanNetworks defer their answer, so those
 * go through a real mt_im (mt_im_on_msg) whose send port records the InvokeResponse.
 * Expected values: spec 1.3 sections 11.9, 11.12, 11.19 as implemented by connectedhomeip v1.3 (see the sources). */
#include "mt_netcomm.h"
#include "mt_gendiag.h"
#include "mt_admincomm.h"

#define NC MT_NETCOMM_CLUSTER_ID
#define GD MT_GENDIAG_CLUSTER_ID
#define AD MT_ADMIN_CLUSTER_ID

/* ---- fake network port ---- */

typedef struct {
    bool has_saved, on, cur_ok, enabled_arg;
    uint8_t saved_ssid[32], on_ssid[32], conn_ssid[32], conn_cred[64];
    size_t saved_len, on_len, conn_len, conn_cred_len;
    uint8_t saved_cred[64];
    size_t saved_cred_len;
    bool conn_has_creds;
    size_t scan_ssid_len;
    int saves, erases, connects, reverts, scans, enables, cur_calls, restores;
    struct { bool has; uint8_t ssid[32], cred[64]; size_t ssid_len, cred_len; } prev; /* before the last save/erase */
    mt_err connect_err, scan_err, save_err, enable_err;
    mt_netctl_ap aps[16];
    int n_aps;
} nfake;

static bool n_saved(void *c, uint8_t s[32], size_t *l)
{
    nfake *f = c;
    if (!f->has_saved) return false;
    memcpy(s, f->saved_ssid, f->saved_len);
    *l = f->saved_len;
    return true;
}
static void n_keep_prev(nfake *f)
{
    f->prev.has = f->has_saved;
    memcpy(f->prev.ssid, f->saved_ssid, sizeof f->prev.ssid);
    memcpy(f->prev.cred, f->saved_cred, sizeof f->prev.cred);
    f->prev.ssid_len = f->saved_len;
    f->prev.cred_len = f->saved_cred_len;
}
static mt_err n_save(void *c, mt_span ssid, mt_span cred)
{
    nfake *f = c;
    f->saves++;
    if (f->save_err) return f->save_err;
    n_keep_prev(f);
    f->has_saved = true;
    memcpy(f->saved_ssid, ssid.p, ssid.len);
    f->saved_len = ssid.len;
    memcpy(f->saved_cred, cred.p, cred.len);
    f->saved_cred_len = cred.len;
    return MT_OK;
}
static mt_err n_erase(void *c)
{
    nfake *f = c;
    f->erases++;
    n_keep_prev(f);
    f->has_saved = false;
    return MT_OK;
}
static mt_err n_restore(void *c)
{
    nfake *f = c;
    f->restores++;
    f->has_saved = f->prev.has;
    memcpy(f->saved_ssid, f->prev.ssid, sizeof f->saved_ssid);
    memcpy(f->saved_cred, f->prev.cred, sizeof f->saved_cred);
    f->saved_len = f->prev.ssid_len;
    f->saved_cred_len = f->prev.cred_len;
    return MT_OK;
}
static bool n_connected(void *c, uint8_t s[32], size_t *l)
{
    nfake *f = c;
    if (!f->on) return false;
    memcpy(s, f->on_ssid, f->on_len);
    *l = f->on_len;
    return true;
}
static bool n_is_current(void *c, mt_span ssid, mt_span cred)
{
    nfake *f = c;
    (void)ssid; (void)cred;
    f->cur_calls++;
    return f->cur_ok;
}
static mt_err n_connect(void *c, mt_span ssid, const mt_span *cred)
{
    nfake *f = c;
    f->connects++;
    memcpy(f->conn_ssid, ssid.p, ssid.len);
    f->conn_len = ssid.len;
    f->conn_has_creds = cred != NULL;
    f->conn_cred_len = cred ? cred->len : 0;
    if (cred) memcpy(f->conn_cred, cred->p, cred->len);
    return f->connect_err;
}
static void n_revert(void *c) { ((nfake *)c)->reverts++; }
static mt_err n_scan(void *c, mt_span ssid)
{
    nfake *f = c;
    f->scans++;
    f->scan_ssid_len = ssid.len;
    return f->scan_err;
}
static bool n_scan_result(void *c, uint16_t idx, mt_netctl_ap *out)
{
    nfake *f = c;
    if (idx >= f->n_aps) return false;
    *out = f->aps[idx];
    return true;
}
static mt_err n_set_enabled(void *c, bool en)
{
    nfake *f = c;
    f->enables++;
    f->enabled_arg = en;
    return f->enable_err;
}
static const mt_netctl_ops NOPS = { n_saved, n_save, n_erase, n_connected, n_is_current, n_connect, n_revert, n_scan,
                                    n_scan_result, n_set_enabled, n_restore };

/* ---- fake diagnostics and admin ports ---- */

typedef struct {
    uint32_t ms;
    bool have_iface;
    mt_gendiag_iface iface;
    int triggers;
    uint64_t last_trigger;
    mt_err trigger_err;
    uint8_t key[16];
} gfake;

static uint32_t g_now_ms(void *c) { return ((gfake *)c)->ms; }
static bool g_iface(void *c, mt_gendiag_iface *out)
{
    gfake *f = c;
    if (!f->have_iface) return false;
    *out = f->iface;
    return true;
}
static mt_err g_trigger(void *c, uint64_t t)
{
    gfake *f = c;
    f->triggers++;
    f->last_trigger = t;
    return f->trigger_err;
}

typedef struct {
    uint8_t status;
    int opens, closes;
    mt_err open_err;
    mt_admin_window w;      /* copy; the salt is copied into salt[] */
    uint8_t salt[32];
    size_t salt_len;
} afake;

static uint8_t a_status(void *c) { return ((afake *)c)->status; }
static mt_err a_open(void *c, const mt_admin_window *w)
{
    afake *f = c;
    f->opens++;
    f->w = *w;
    f->salt_len = w->salt.len;
    memcpy(f->salt, w->salt.p, w->salt.len);
    if (f->open_err) return f->open_err;
    f->status = MT_WINDOW_ENHANCED;
    return MT_OK;
}
static void a_close(void *c)
{
    afake *f = c;
    f->closes++;
    f->status = MT_WINDOW_NOT_OPEN;
}
static const mt_admin_ops AOPS = { a_status, a_open, a_close };

/* ---- the IM that carries deferred answers ---- */

static struct {
    mt_netcomm nc;
    mt_gendiag gd;
    mt_admin ad;
    nfake nf;
    gfake gf;
    afake af;
    mt_im im;
    uint8_t tx[1280], scratch[MT_NETCOMM_SCRATCH];
    int nsent, holds;
    struct { uint16_t session, exch; uint8_t op; size_t len; uint8_t p[1300]; } last;
} CT;

static mt_err ct_send(void *c, uint16_t session, uint16_t *exch, uint8_t op, mt_span p, bool expect)
{
    (void)c; (void)expect;
    CT.nsent++;
    CT.last.session = session;
    CT.last.exch = *exch;
    CT.last.op = op;
    CT.last.len = p.len;
    memcpy(CT.last.p, p.p, p.len);
    return MT_OK;
}
static uint32_t ct_now(void *c) { (void)c; return F.now; }
static void ct_hold(void *c, uint16_t exch) { (void)c; (void)exch; CT.holds++; }
static const mt_im_ports CT_PORTS = { ct_send, ct_now, ct_hold };

/* A fresh node with the three clusters in endpoint 0. commissioned: fabric 1 exists, session S_CASE1 is its admin. */
static void ct_init(bool commissioned)
{
    memset(&CT, 0, sizeof CT);
    fx_init(false);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    CT.gf.ms = 0xFFFFF000u;
    memset(CT.gf.key, 0xA5, sizeof CT.gf.key);
    mt_netcomm_cfg nc = { &NOPS, &CT.nf, &F.r, (1u << MT_WIFI_BAND_2G4) | (1u << MT_WIFI_BAND_5G), 12, 25, false,
                          mt_buf_of(CT.scratch, sizeof CT.scratch) };
    CHECK(mt_netcomm_init(&CT.nc, &nc) == MT_OK);
    mt_gendiag_cfg gc = { &CT.gf, g_now_ms, g_iface, g_trigger, CT.gf.key, 7, MT_BOOT_SW_WATCHDOG };
    CHECK(mt_gendiag_init(&CT.gd, &gc) == MT_OK);
    mt_admin_cfg ac = { &AOPS, &CT.af, &F.r };
    CHECK(mt_admin_init(&CT.ad, &ac) == MT_OK);
    F.cls0[7] = &CT.nc.cluster; F.cls0[8] = &CT.gd.cluster; F.cls0[9] = &CT.ad.cluster;
    F.eps[0].n_clusters = 10;
    mt_im_cfg ic = { &mt_dm_im, &F.dm, &CT_PORTS, NULL, mt_buf_of(CT.tx, sizeof CT.tx), 1, 0 };
    mt_im_init(&CT.im, &ic);
    mt_dm_cfg dc = { &F.node, &CT.im, mt_root_access, &F.r, 1 };
    CHECK(mt_dm_init(&F.dm, &dc) == MT_OK);
    mt_root_bind_dm(&F.r, &F.dm);
    if (commissioned) commission_first();
}

static mt_span sp(const char *s) { return mt_span_of((const uint8_t *)s, strlen(s)); }

/* Send an InvokeRequest for endpoint 0 through the IM engine; `w` holds the command fields (or NULL). */
static uint8_t g_imreq[1500];
static void im_inv(int sid, uint16_t exch, uint32_t cl, uint32_t cmd, mt_tlv_wr *w, bool timed)
{
    mt_tlv_wr o;
    mt_span f = mt_span_of(NULL, 0);
    mt_im_subject s = subj(sid);
    if (w) {
        mt_span all;
        mt_tlv_end(w);
        all = mt_tlv_wr_span(w);
        f = mt_span_of(all.p + 1, all.len - 2); /* the members without the struct frame */
    }
    mt_tlv_wr_init(&o, mt_buf_of(g_imreq, sizeof g_imreq));
    mt_tlv_start(&o, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bool(&o, mt_tlv_ctx(0), false);
    mt_tlv_put_bool(&o, mt_tlv_ctx(1), timed);
    mt_tlv_start(&o, mt_tlv_ctx(2), MT_TLV_ARRAY);
    mt_tlv_start(&o, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_start(&o, mt_tlv_ctx(0), MT_TLV_LIST);
    mt_tlv_put_u(&o, mt_tlv_ctx(0), 0);
    mt_tlv_put_u(&o, mt_tlv_ctx(1), cl);
    mt_tlv_put_u(&o, mt_tlv_ctx(2), cmd);
    mt_tlv_end(&o);
    mt_tlv_start(&o, mt_tlv_ctx(1), MT_TLV_STRUCT);
    if (f.len) mt_tlv_put_raw(&o, f);
    mt_tlv_end(&o);
    mt_tlv_end(&o);
    mt_tlv_end(&o);
    mt_tlv_put_u(&o, mt_tlv_ctx(0xFF), 11);
    mt_tlv_end(&o);
    mt_im_on_msg(&CT.im, &s, exch, MT_IM_OP_INVOKE, mt_tlv_wr_span(&o));
}

/* Parse the last InvokeResponse: 0 = response data (*rc, *o inside its fields), 1 = status (*st, *cst or -1), -1 = bad. */
static int ct_parse(uint32_t *rc, mt_tlv_rd *o, int *st, int *cst)
{
    mt_tlv_rd r, ib, x, cd, y;
    uint64_t v;
    mt_tlv_rd_init(&r, mt_span_of(CT.last.p, CT.last.len));
    if (CT.last.op != MT_IM_OP_INVOKE_RESP || mt_tlv_next(&r) || mt_tlv_enter(&r) || mt_tlv_find_ctx(&r, 1) ||
        mt_tlv_enter(&r) || mt_tlv_next(&r) || mt_tlv_enter(&r))
        return -1;
    ib = r;
    x = ib;
    if (!mt_tlv_find_ctx(&x, 0)) {
        mt_tlv_enter(&x);
        cd = x;
        if (mt_tlv_find_ctx(&x, 0) || mt_tlv_enter(&x) || mt_tlv_find_ctx(&x, 2) || mt_tlv_get_u64(&x, &v)) return -1;
        *rc = (uint32_t)v;
        x = cd;
        if (mt_tlv_find_ctx(&x, 1) || mt_tlv_enter(&x)) return -1;
        *o = x;
        return 0;
    }
    x = ib;
    if (mt_tlv_find_ctx(&x, 1) || mt_tlv_enter(&x) || mt_tlv_find_ctx(&x, 1) || mt_tlv_enter(&x)) return -1;
    y = x;
    if (mt_tlv_find_ctx(&y, 0) || mt_tlv_get_u64(&y, &v)) return -1;
    *st = (int)v;
    y = x;
    *cst = !mt_tlv_find_ctx(&y, 1) && !mt_tlv_get_u64(&y, &v) ? (int)v : -1;
    return 1;
}
/* The last response is response data `want_rc` whose field 0 is `code`. */
static bool ct_resp(uint32_t want_rc, int code)
{
    uint32_t rc = 0;
    mt_tlv_rd o;
    uint64_t v;
    return ct_parse(&rc, &o, &(int){ 0 }, &(int){ 0 }) == 0 && rc == want_rc && field_u(&o, 0, &v) && (int)v == code;
}
/* The last response is a status answer `st` (and cluster status `cst`, -1 = none). */
static bool ct_status(int st, int cst)
{
    uint32_t rc;
    mt_tlv_rd o;
    int s = -9, c = -9;
    return ct_parse(&rc, &o, &s, &c) == 1 && s == st && c == cst;
}

/* ---- Network Commissioning helpers ---- */

static int add_wifi(int sid, mt_span ssid, mt_span cred, int64_t crumb, mt_im_status *stp, uint8_t *idx)
{
    mt_tlv_wr *w = req();
    uint32_t rc;
    mt_tlv_rd o;
    uint64_t v;
    int code;
    memset(&o, 0, sizeof o);
    mt_tlv_put_bytes(w, mt_tlv_ctx(0), ssid);
    mt_tlv_put_bytes(w, mt_tlv_ctx(1), cred);
    if (crumb >= 0) mt_tlv_put_u(w, mt_tlv_ctx(2), (uint64_t)crumb);
    mt_im_status st = invoke(sid, NC, 2, w, &rc, &o);
    if (stp) *stp = st;
    code = code_of(st, rc, 5, &o);
    if (idx) *idx = code == 0 && field_u(&o, 2, &v) ? (uint8_t)v : 0xFF;
    return code;
}
static int remove_net(int sid, mt_span id, mt_im_status *stp)
{
    mt_tlv_wr *w = req();
    uint32_t rc;
    mt_tlv_rd o;
    memset(&o, 0, sizeof o);
    mt_tlv_put_bytes(w, mt_tlv_ctx(0), id);
    mt_im_status st = invoke(sid, NC, 4, w, &rc, &o);
    if (stp) *stp = st;
    return code_of(st, rc, 5, &o);
}
static int reorder_net(int sid, mt_span id, unsigned index, mt_im_status *stp)
{
    mt_tlv_wr *w = req();
    uint32_t rc;
    mt_tlv_rd o;
    memset(&o, 0, sizeof o);
    mt_tlv_put_bytes(w, mt_tlv_ctx(0), id);
    mt_tlv_put_u(w, mt_tlv_ctx(1), index);
    mt_im_status st = invoke(sid, NC, 8, w, &rc, &o);
    if (stp) *stp = st;
    return code_of(st, rc, 5, &o);
}
static void im_connect(int sid, uint16_t exch, mt_span id, int64_t crumb)
{
    mt_tlv_wr *w = req();
    mt_tlv_put_bytes(w, mt_tlv_ctx(0), id);
    if (crumb >= 0) mt_tlv_put_u(w, mt_tlv_ctx(1), (uint64_t)crumb);
    im_inv(sid, exch, NC, 6, w, false);
}
static void im_scan(int sid, uint16_t exch, const char *ssid, int64_t crumb)
{
    mt_tlv_wr *w = req();
    if (ssid) mt_tlv_put_bytes(w, mt_tlv_ctx(0), sp(ssid));
    if (crumb >= 0) mt_tlv_put_u(w, mt_tlv_ctx(1), (uint64_t)crumb);
    im_inv(sid, exch, NC, 0, w, false);
}
static bool net_is(const char *ssid, bool connected)
{
    mt_tlv_rd r, x;
    mt_span s;
    bool b;
    if (rd(S_PASE, false, NC, 1, 0, &r) != MT_OK) return false;
    x = r;
    if (mt_tlv_enter(&x) || !field_b(&x, 0, &s) || !span_eq(s, sp(ssid))) return false;
    x = r;
    mt_tlv_enter(&x);
    return !mt_tlv_find_ctx(&x, 1) && !mt_tlv_get_bool(&x, &b) && b == connected;
}
static bool is_null(uint32_t cl, uint32_t attr)
{
    mt_tlv_rd r;
    return rd(S_PASE, false, cl, attr, 0, &r) == MT_OK && r.type == MT_TLV_NULL;
}
static bool bytes_is(uint32_t cl, uint32_t attr, mt_span want)
{
    mt_tlv_rd r;
    mt_span b;
    return rd(S_PASE, false, cl, attr, 0, &r) == MT_OK && !mt_tlv_get_bytes(&r, &b) && span_eq(b, want);
}
static void stage_home(void)
{
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    CHECK(add_wifi(S_CASE1, sp("home"), sp("password1"), -1, NULL, NULL) == MT_NET_OK);
}

/* ---- Network Commissioning ---- */

static void test_netcomm_attrs(void)
{
    mt_tlv_rd r;
    uint64_t v;
    bool b;
    mt_netcomm_cfg c = { &NOPS, &CT.nf, NULL, 1, 0, 0, false, mt_buf_of(CT.scratch, sizeof CT.scratch) };
    mt_netctl_ops bad = NOPS;
    ct_init(false);
    CHECK(rd_u(NC, 0, 1) && rd_u(NC, 2, 12) && rd_u(NC, 3, 25) && rd_u(NC, 0xFFFD, 2) && rd_u(NC, 0xFFFC, 1));
    CHECK(rd(S_PASE, false, NC, 4, 0, &r) == MT_OK && !mt_tlv_get_bool(&r, &b) && b);
    CHECK(is_null(NC, 5) && is_null(NC, 6) && is_null(NC, 7));
    CHECK(list_len(S_PASE, false, NC, 1) == 0);
    CHECK(list_len(S_PASE, false, NC, 8) == 2);
    CHECK(rd(S_PASE, false, NC, 8, 0, &r) == MT_OK && !mt_tlv_get_u64(&r, &v) && v == MT_WIFI_BAND_2G4);
    CHECK(rd(S_PASE, false, NC, 8, 1, &r) == MT_OK && !mt_tlv_get_u64(&r, &v) && v == MT_WIFI_BAND_5G);
    CHECK(list_len(S_PASE, false, NC, 0xFFF9) == 5 && list_len(S_PASE, false, NC, 0xFFF8) == 3);
    /* a persisted network shows up, connected or not */
    CT.nf.has_saved = true; CT.nf.saved_len = 4; memcpy(CT.nf.saved_ssid, "home", 4);
    CHECK(list_len(S_PASE, false, NC, 1) == 1 && net_is("home", false));
    CT.nf.on = true; CT.nf.on_len = 4; memcpy(CT.nf.on_ssid, "home", 4);
    CHECK(net_is("home", true));
    CT.nf.on_ssid[0] = 'x';
    CHECK(net_is("home", false));
    /* InterfaceEnabled: written through to the port */
    mt_tlv_wr tw;
    mt_tlv_wr_init(&tw, mt_buf_of(g_req, sizeof g_req));
    mt_tlv_put_bool(&tw, mt_tlv_anon(), false);
    CHECK(wr(S_PASE, NC, 4, MT_IM_WR_VALUE, &tw) == MT_IM_SUCCESS && CT.nf.enables == 1 && !CT.nf.enabled_arg);
    CHECK(rd(S_PASE, false, NC, 4, 0, &r) == MT_OK && !mt_tlv_get_bool(&r, &b) && !b);
    CT.nf.enable_err = MT_ERR_IO;
    mt_tlv_wr_init(&tw, mt_buf_of(g_req, sizeof g_req));
    mt_tlv_put_bool(&tw, mt_tlv_anon(), true);
    CHECK(wr(S_PASE, NC, 4, MT_IM_WR_VALUE, &tw) == MT_IM_FAILURE);
    CHECK(rd(S_PASE, false, NC, 4, 0, &r) == MT_OK && !mt_tlv_get_bool(&r, &b) && !b); /* unchanged */
    mt_tlv_wr_init(&tw, mt_buf_of(g_req, sizeof g_req));
    mt_tlv_put_u(&tw, mt_tlv_anon(), 1);
    CHECK(wr(S_PASE, NC, 4, MT_IM_WR_VALUE, &tw) == MT_IM_INVALID_DATA_TYPE);
    mt_tlv_wr_init(&tw, mt_buf_of(g_req, sizeof g_req));
    mt_tlv_put_bool(&tw, mt_tlv_anon(), true);
    CHECK(wr(S_PASE, NC, 4, MT_IM_WR_LIST_APPEND, &tw) == MT_IM_INVALID_ACTION);
    /* init checks */
    CHECK(mt_netcomm_init(&CT.nc, &c) == MT_ERR_INVALID);                  /* no root */
    c.root = &F.r; c.scratch.cap = MT_NETCOMM_SCRATCH - 1;
    CHECK(mt_netcomm_init(&CT.nc, &c) == MT_ERR_INVALID);                  /* scratch too small */
    c.scratch.cap = MT_NETCOMM_SCRATCH; c.bands = 0;
    CHECK(mt_netcomm_init(&CT.nc, &c) == MT_ERR_INVALID);                  /* no band */
    c.bands = 1; bad.scan = NULL; c.net = &bad;
    CHECK(mt_netcomm_init(&CT.nc, &c) == MT_ERR_INVALID);                  /* a required op missing */
    bad = NOPS; bad.is_current = NULL; bad.set_enabled = NULL; c.net = &bad;
    CHECK(mt_netcomm_init(&CT.nc, &c) == MT_OK);                           /* optional ops */
    CHECK(CT.nc.c.scan_max_s == 10 && CT.nc.c.connect_max_s == 30);        /* defaults */
}

static void test_netcomm_staging(void)
{
    mt_im_status st;
    uint8_t idx;
    uint8_t long33[33], long65[65], hex64[64], bad64[64];
    memset(long33, 'a', sizeof long33);
    memset(long65, 'a', sizeof long65);
    memset(hex64, 'F', sizeof hex64);
    memset(bad64, '0', sizeof bad64);
    bad64[63] = 'g';
    ct_init(true);
    /* fail-safe first, then the argument checks (chip order) */
    CHECK(add_wifi(S_CASE1, sp("home"), sp("password1"), -1, &st, NULL) == -1 && st == MT_IM_FAILSAFE_REQUIRED);
    CHECK(add_wifi(S_CASE1, sp(""), sp("password1"), -1, &st, NULL) == -1 && st == MT_IM_FAILSAFE_REQUIRED);
    CHECK(remove_net(S_CASE1, sp("home"), &st) == -1 && st == MT_IM_FAILSAFE_REQUIRED);
    CHECK(reorder_net(S_CASE1, sp("home"), 0, &st) == -1 && st == MT_IM_FAILSAFE_REQUIRED);
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    /* argument checks */
    CHECK(add_wifi(S_CASE1, sp(""), sp("password1"), -1, &st, NULL) == -1 && st == MT_IM_CONSTRAINT_ERROR);
    CHECK(add_wifi(S_CASE1, mt_span_of(long33, 33), sp("password1"), -1, &st, NULL) == -1 && st == MT_IM_CONSTRAINT_ERROR);
    CHECK(add_wifi(S_CASE1, sp("home"), sp("1234567"), -1, &st, NULL) == -1 && st == MT_IM_CONSTRAINT_ERROR);
    CHECK(add_wifi(S_CASE1, sp("home"), mt_span_of(long65, 65), -1, &st, NULL) == -1 && st == MT_IM_CONSTRAINT_ERROR);
    CHECK(add_wifi(S_CASE1, sp("home"), mt_span_of(long33, 33), -1, NULL, NULL) == MT_NET_OK); /* a 33-char passphrase */
    CT.nc.stage.kind = 0;
    CHECK(add_wifi(S_CASE1, sp("home"), mt_span_of(bad64, 64), -1, &st, NULL) == -1 && st == MT_IM_CONSTRAINT_ERROR);
    CHECK(list_len(S_PASE, false, NC, 1) == 0 && CT.nc.stage.kind == 0);
    {   /* missing credentials, NetworkIdentity (PDC) */
        mt_tlv_wr *w = req();
        uint32_t rc;
        mt_tlv_put_bytes(w, mt_tlv_ctx(0), sp("home"));
        CHECK(invoke(S_CASE1, NC, 2, w, &rc, NULL) == MT_IM_INVALID_COMMAND);
        w = req();
        mt_tlv_put_bytes(w, mt_tlv_ctx(0), sp("home"));
        mt_tlv_put_bytes(w, mt_tlv_ctx(1), sp("password1"));
        mt_tlv_put_bytes(w, mt_tlv_ctx(3), sp("id"));
        CHECK(invoke(S_CASE1, NC, 2, w, &rc, NULL) == MT_IM_INVALID_COMMAND);
        CHECK(invoke(S_CASE1, NC, 2, NULL, &rc, NULL) == MT_IM_INVALID_COMMAND);
        CHECK(invoke(S_CASE1, NC, 3, NULL, &rc, NULL) == MT_IM_UNSUPPORTED_COMMAND);
    }
    /* valid shapes: open, WEP-64, passphrase, 64 hex digits */
    CHECK(add_wifi(S_CASE1, sp("home"), sp(""), -1, NULL, NULL) == MT_NET_OK);
    CHECK(add_wifi(S_CASE1, sp("home"), sp("12345"), -1, NULL, NULL) == MT_NET_OK);
    CHECK(add_wifi(S_CASE1, sp("home"), mt_span_of(hex64, 64), -1, NULL, NULL) == MT_NET_OK);
    /* staged: visible in Networks, persisted nowhere; the response carries NetworkIndex 0 and the breadcrumb */
    CHECK(add_wifi(S_CASE1, sp("home"), sp("password1"), 42, NULL, &idx) == MT_NET_OK && idx == 0);
    CHECK(list_len(S_PASE, false, NC, 1) == 1 && net_is("home", false) && rd_u(GC, 0, 42));
    CHECK(CT.nf.saves == 0 && !CT.nf.has_saved && (F.r.fs.flags & MT_FS_NETWORK));
    /* another SSID: the one slot is taken (BoundsExceeded), the same SSID is an update */
    CHECK(add_wifi(S_CASE1, sp("other"), sp("password1"), -1, NULL, NULL) == MT_NET_BOUNDS_EXCEEDED);
    CHECK(net_is("home", false));
    CHECK(add_wifi(S_CASE1, sp("home"), sp("password2"), -1, NULL, NULL) == MT_NET_OK);
    CHECK(CT.nc.stage.cred_len == 9 && !memcmp(CT.nc.stage.cred, "password2", 9));
    /* fail-safe expiry drops it; nothing persisted, the station was not moved */
    mt_root_failsafe_expire(&F.r);
    CHECK(list_len(S_PASE, false, NC, 1) == 0 && CT.nc.stage.kind == 0 && CT.nf.saves == 0 && CT.nf.reverts == 0);
    CHECK(rd_u(GC, 0, 0));
    /* CommissioningComplete persists it */
    stage_home();
    CHECK(complete(S_CASE1, &st) == MT_COMM_OK);
    CHECK(CT.nf.saves == 1 && CT.nf.saved_len == 4 && !memcmp(CT.nf.saved_ssid, "home", 4) &&
          CT.nf.saved_cred_len == 9 && !memcmp(CT.nf.saved_cred, "password1", 9) && CT.nc.stage.kind == 0);
    CHECK(net_is("home", false) && CT.nc.stage.cred_len == 0);
    /* a save that fails keeps the fail-safe armed and answers FAILURE (the stage stays) */
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    CHECK(add_wifi(S_CASE1, sp("home"), sp("password3"), -1, NULL, NULL) == MT_NET_OK);
    CT.nf.save_err = MT_ERR_IO;
    CHECK(complete(S_CASE1, &st) == -1 && st == MT_IM_FAILURE && mt_root_failsafe_armed(&F.r) && CT.nc.stage.kind == 1);
    CT.nf.save_err = MT_OK;
    CHECK(complete(S_CASE1, &st) == MT_COMM_OK && CT.nf.saves == 3 && !memcmp(CT.nf.saved_cred, "password3", 9));
    /* a different SSID over a persisted one: BoundsExceeded, or replaced when the config says so */
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    CHECK(add_wifi(S_CASE1, sp("new"), sp("password1"), -1, NULL, NULL) == MT_NET_BOUNDS_EXCEEDED);
    CT.nc.c.replace_when_full = true;
    CHECK(add_wifi(S_CASE1, sp("new"), sp("password1"), -1, NULL, NULL) == MT_NET_OK && net_is("new", false));
    mt_root_failsafe_expire(&F.r);
    CT.nc.c.replace_when_full = false;
    CHECK(net_is("home", false));
    /* RemoveNetwork: unknown id, then staged removal; committed at CommissioningComplete, dropped on expiry */
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    CHECK(remove_net(S_CASE1, sp("nope"), NULL) == MT_NET_ID_NOT_FOUND);
    CT.nc.have_status = true;  /* a Last* result that a removal clears */
    CHECK(remove_net(S_CASE1, sp("home"), NULL) == MT_NET_OK);
    CHECK(list_len(S_PASE, false, NC, 1) == 0 && CT.nf.erases == 0 && is_null(NC, 5));
    mt_root_failsafe_expire(&F.r);
    CHECK(net_is("home", false) && CT.nf.erases == 0);
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK && remove_net(S_CASE1, sp("home"), NULL) == MT_NET_OK);
    CHECK(complete(S_CASE1, &st) == MT_COMM_OK && CT.nf.erases == 1 && !CT.nf.has_saved && list_len(S_PASE, false, NC, 1) == 0);
    /* a staged network on an empty slot that is removed again: no erase at commit */
    stage_home();
    CHECK(remove_net(S_CASE1, sp("home"), NULL) == MT_NET_OK && CT.nc.stage.kind == 0 && list_len(S_PASE, false, NC, 1) == 0);
    CHECK(complete(S_CASE1, &st) == MT_COMM_OK && CT.nf.erases == 1 && CT.nf.saves == 3);
    /* ReorderNetwork: one slot */
    stage_home();
    CHECK(reorder_net(S_CASE1, sp("nope"), 0, NULL) == MT_NET_ID_NOT_FOUND);
    CHECK(reorder_net(S_CASE1, sp("home"), 1, NULL) == MT_NET_OUT_OF_RANGE);
    CHECK(reorder_net(S_CASE1, sp("home"), 0, NULL) == MT_NET_OK);
    {
        mt_tlv_wr *w = req();
        uint32_t rc;
        mt_tlv_put_bytes(w, mt_tlv_ctx(0), sp("home"));
        CHECK(invoke(S_CASE1, NC, 8, w, &rc, NULL) == MT_IM_INVALID_COMMAND); /* NetworkIndex missing */
    }
    /* another fabric's fail-safe is no fail-safe for us */
    fx_session(S_CASE2, MT_IM_AUTH_CASE, 2, 5);
    CHECK(add_wifi(S_CASE2, sp("home"), sp("password1"), -1, &st, NULL) == -1 && st == MT_IM_FAILSAFE_REQUIRED);
}

static void test_netcomm_connect(void)
{
    mt_tlv_rd o;
    uint32_t rc;
    int s, c, n;
    int32_t e32;
    ct_init(true);
    /* no fail-safe */
    im_connect(S_CASE1, 70, sp("home"), -1);
    CHECK(CT.nsent == 1 && ct_status(MT_IM_FAILSAFE_REQUIRED, -1));
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    /* unknown network: immediate response, recorded */
    im_connect(S_CASE1, 71, sp("nope"), -1);
    CHECK(CT.nsent == 2 && ct_resp(7, MT_NET_ID_NOT_FOUND) && CT.nf.connects == 0);
    CHECK(rd_u(NC, 5, MT_NET_ID_NOT_FOUND) && bytes_is(NC, 6, sp("nope")) && is_null(NC, 7));
    /* a staged network, station elsewhere: the join starts, the answer waits */
    CHECK(add_wifi(S_CASE1, sp("home"), sp("password1"), -1, NULL, NULL) == MT_NET_OK);
    im_connect(S_CASE1, 72, sp("home"), 99);
    CHECK(CT.nsent == 2 && CT.holds == 1 && CT.nf.connects == 1 && CT.nf.conn_has_creds && CT.nf.conn_cred_len == 9 &&
          !memcmp(CT.nf.conn_cred, "password1", 9) && CT.nf.conn_len == 4);
    CHECK(mt_netcomm_poll(&CT.nc) == 25000);
    F.now += 5000;
    CHECK(mt_netcomm_poll(&CT.nc) == 20000 && CT.nsent == 2);
    /* busy meanwhile, for every command */
    CHECK(reorder_net(S_CASE1, sp("home"), 0, &(mt_im_status){ 0 }) == -1);
    CHECK(invoke(S_CASE1, NC, 4, NULL, &rc, NULL) == MT_IM_BUSY && invoke(S_CASE1, NC, 0, NULL, &rc, NULL) == MT_IM_BUSY);
    /* success: response, Last* attributes, breadcrumb */
    mt_netcomm_connect_done(&CT.nc, MT_NET_OK, NULL);
    CHECK(CT.nsent == 3 && CT.last.exch == 72 && CT.last.session == S_CASE1 && ct_resp(7, MT_NET_OK));
    CHECK(ct_parse(&rc, &o, &s, &c) == 0 && !mt_tlv_find_ctx(&o, 2) && o.type == MT_TLV_NULL);
    CHECK(rd_u(NC, 5, MT_NET_OK) && bytes_is(NC, 6, sp("home")) && is_null(NC, 7) && rd_u(GC, 0, 99));
    CHECK(mt_netcomm_poll(&CT.nc) == UINT32_MAX);
    mt_netcomm_connect_done(&CT.nc, MT_NET_OK, NULL);   /* late/duplicate result: ignored */
    mt_netcomm_scan_done(&CT.nc, MT_NET_OK);
    CHECK(CT.nsent == 3);
    /* the join moved the station: expiry goes back, once */
    CT.nf.on = true; CT.nf.on_len = 4; memcpy(CT.nf.on_ssid, "home", 4);
    CHECK(net_is("home", true));
    mt_root_failsafe_expire(&F.r);
    CHECK(CT.nf.reverts == 1 && CT.nc.stage.kind == 0 && list_len(S_PASE, false, NC, 1) == 0);
    mt_root_failsafe_expire(&F.r);
    CHECK(CT.nf.reverts == 1);

    /* failure: status and the platform error value in the response and in LastConnectErrorValue; no breadcrumb */
    CT.nf.on = false;
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    CHECK(add_wifi(S_CASE1, sp("home"), sp("password1"), -1, NULL, NULL) == MT_NET_OK);
    im_connect(S_CASE1, 73, sp("home"), 55);
    e32 = -5;
    mt_netcomm_connect_done(&CT.nc, MT_NET_AUTH_FAILURE, &e32);
    CHECK(CT.nsent == 4 && ct_resp(7, MT_NET_AUTH_FAILURE) && ct_parse(&rc, &o, &s, &c) == 0 &&
          !mt_tlv_find_ctx(&o, 2) && !mt_tlv_get_i32(&o, &e32) && e32 == -5);
    {
        mt_tlv_rd r;
        int32_t got;
        CHECK(rd_u(NC, 5, MT_NET_AUTH_FAILURE) && rd(S_PASE, false, NC, 7, 0, &r) == MT_OK && !mt_tlv_get_i32(&r, &got) && got == -5);
        CHECK(rd_u(GC, 0, 1)); /* the breadcrumb of the arm, not 55 */
    }
    /* the port refuses to start: answered at once with OtherConnectionFailure */
    CT.nf.connect_err = MT_ERR_IO;
    n = CT.holds;
    im_connect(S_CASE1, 74, sp("home"), -1);
    CHECK(CT.nsent == 5 && CT.holds == n && ct_resp(7, MT_NET_OTHER_CONNECTION_FAILURE) && CT.nc.op.kind == 0);
    CT.nf.connect_err = MT_OK;
    /* already on the staged network with the same credentials: success at once, nothing started */
    CT.nf.on = true; CT.nf.on_len = 4; memcpy(CT.nf.on_ssid, "home", 4);
    CT.nf.cur_ok = true;
    n = CT.nf.connects;
    im_connect(S_CASE1, 75, sp("home"), -1);
    CHECK(CT.nsent == 6 && ct_resp(7, MT_NET_OK) && CT.nf.connects == n && CT.nf.cur_calls == 1 && CT.holds == 1 + 1 + 0 + 0 + 1 - 1);
    /* ... but different credentials rejoin */
    CT.nf.cur_ok = false;
    im_connect(S_CASE1, 76, sp("home"), -1);
    CHECK(CT.nsent == 6 && CT.nf.connects == n + 1);
    mt_netcomm_connect_done(&CT.nc, MT_NET_OK, NULL);
    CHECK(CT.nsent == 7 && ct_resp(7, MT_NET_OK));
    /* CommissioningComplete keeps the new network and forgets the revert */
    {
        mt_im_status st;
        int r0 = CT.nf.reverts;
        CHECK(complete(S_CASE1, &st) == MT_COMM_OK && CT.nf.saves == 1 && !CT.nc.switched);
        CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
        mt_root_failsafe_expire(&F.r);
        CHECK(CT.nf.reverts == r0);
    }
    /* persisted and connected: success at once without asking is_current */
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    n = CT.nf.cur_calls;
    im_connect(S_CASE1, 77, sp("home"), 8);
    CHECK(ct_resp(7, MT_NET_OK) && CT.nf.cur_calls == n && rd_u(GC, 0, 8));
    /* timeout: poll ends a join that never reports, as a failure */
    CT.nf.on = false;
    im_connect(S_CASE1, 78, sp("home"), -1);
    CHECK(CT.nc.op.kind == 2 && CT.nsent == 8 - 0);
    n = CT.nsent;
    F.now += 24999;
    CHECK(mt_netcomm_poll(&CT.nc) == 1 && CT.nsent == n);
    F.now += 1;
    CHECK(mt_netcomm_poll(&CT.nc) == UINT32_MAX && CT.nsent == n + 1 && ct_resp(7, MT_NET_OTHER_CONNECTION_FAILURE) &&
          CT.nc.op.kind == 0);
    /* fail-safe expiry with a join in flight: the controller gets a failure (from the next poll, never inside the
     * expiry), the old network comes back; a late port result does not turn it into a success */
    im_connect(S_CASE1, 79, sp("home"), -1);
    n = CT.nsent;
    mt_root_failsafe_expire(&F.r);
    CHECK(CT.nsent == n && CT.nf.reverts >= 1 && CT.nc.op.kind == 2);
    mt_netcomm_connect_done(&CT.nc, MT_NET_OK, NULL);
    CHECK(CT.nsent == n + 1 && ct_resp(7, MT_NET_OTHER_CONNECTION_FAILURE) && CT.nc.op.kind == 0);
    /* ArmFailSafe(0) on another exchange while a join runs: its own response goes out intact first, the
     * ConnectNetwork answer follows from the poll (the expiry runs inside the ArmFailSafe invoke, whose response
     * is being built in the same IM buffer) */
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    im_connect(S_CASE1, 81, sp("home"), -1);
    n = CT.nsent;
    {
        mt_tlv_wr *w = req();
        mt_tlv_put_u(w, mt_tlv_ctx(0), 0);
        mt_tlv_put_u(w, mt_tlv_ctx(1), 0);
        im_inv(S_CASE1, 82, GC, 0, w, false);
    }
    CHECK(CT.nsent == n + 1 && CT.last.exch == 82 && ct_resp(1, MT_COMM_OK) && !mt_root_failsafe_armed(&F.r));
    CHECK(mt_netcomm_poll(&CT.nc) == UINT32_MAX && CT.nsent == n + 2 && CT.last.exch == 81 &&
          ct_resp(7, MT_NET_OTHER_CONNECTION_FAILURE) && CT.nc.op.kind == 0);
    /* the exchange dies while the join runs: nothing is sent, the module stays busy until the port reports */
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    im_connect(S_CASE1, 80, sp("home"), -1);
    n = CT.nsent;
    mt_im_on_exchange_failed(&CT.im, 80);
    CHECK(invoke(S_CASE1, NC, 0, NULL, &rc, NULL) == MT_IM_BUSY);
    mt_netcomm_connect_done(&CT.nc, MT_NET_OK, NULL);
    CHECK(CT.nsent == n && CT.nc.op.kind == 0 && invoke(S_CASE1, NC, 8, NULL, &rc, NULL) == MT_IM_INVALID_COMMAND);
}

static mt_netctl_ap ap(const char *ssid, int8_t rssi, uint16_t ch)
{
    mt_netctl_ap a;
    memset(&a, 0, sizeof a);
    a.ssid_len = (uint8_t)strlen(ssid);
    memcpy(a.ssid, ssid, a.ssid_len);
    a.rssi = rssi;
    a.channel = ch;
    a.security = MT_WIFI_SEC_WPA2;
    a.band = MT_WIFI_BAND_2G4;
    a.bssid[5] = (uint8_t)ch;
    return a;
}

static void test_netcomm_scan(void)
{
    mt_tlv_rd o, arr, it;
    uint32_t rc;
    int s, c, n;
    uint64_t v;
    mt_span b;
    ct_init(true);
    CT.nf.aps[0] = ap("far", -80, 1);
    CT.nf.aps[1] = ap("near", -30, 6);
    CT.nf.aps[2] = ap("mid", -55, 11);
    CT.nf.n_aps = 3;
    /* needs no fail-safe; deferred; results sorted strongest first */
    im_scan(S_CASE1, 60, NULL, -1);
    CHECK(CT.nsent == 0 && CT.holds == 1 && CT.nf.scans == 1 && CT.nf.scan_ssid_len == 0);
    CHECK(mt_netcomm_poll(&CT.nc) == 12000);
    CHECK(invoke(S_CASE1, NC, 4, NULL, &rc, NULL) == MT_IM_BUSY);
    mt_netcomm_scan_done(&CT.nc, MT_NET_OK);
    CHECK(CT.nsent == 1 && CT.last.exch == 60 && ct_resp(1, MT_NET_OK) && ct_parse(&rc, &o, &s, &c) == 0);
    CHECK(!mt_tlv_find_ctx(&o, 2) && !mt_tlv_enter(&o));
    arr = o;
    {
        static const char *want[3] = { "near", "mid", "far" };
        static const uint8_t chan[3] = { 6, 11, 1 };
        int i = 0;
        while (!mt_tlv_next(&arr) && i < 4) {
            it = arr;
            CHECK(!mt_tlv_enter(&it) && field_b(&it, 1, &b) && i < 3 && span_eq(b, sp(want[i])));
            CHECK(field_u(&it, 3, &v) && v == chan[i] && field_u(&it, 0, &v) && v == MT_WIFI_SEC_WPA2);
            CHECK(field_b(&it, 2, &b) && b.len == 6 && b.p[5] == chan[i] && field_u(&it, 4, &v) && v == MT_WIFI_BAND_2G4);
            i++;
        }
        CHECK(i == 3);
    }
    CHECK(rd_u(NC, 5, MT_NET_OK) && is_null(NC, 6) && is_null(NC, 7));
    /* an SSID filter, and the breadcrumb on success */
    CT.nf.n_aps = 1;
    im_scan(S_CASE1, 61, "far", 33);
    CHECK(CT.nf.scan_ssid_len == 3 && CT.nc.op.kind == 1);
    mt_netcomm_scan_done(&CT.nc, MT_NET_OK);
    CHECK(ct_resp(1, MT_NET_OK) && rd_u(GC, 0, 33));
    /* at most MT_NETCOMM_MAX_SCAN_RESULTS, and no more than the scratch holds */
    CT.nf.n_aps = 16;
    for (int i = 0; i < 16; i++) {
        char nm[8] = "ap";
        nm[2] = (char)('a' + i);
        nm[3] = 0;
        CT.nf.aps[i] = ap(nm, (int8_t)(-90 + i), (uint16_t)i);
    }
    im_scan(S_CASE1, 62, NULL, -1);
    mt_netcomm_scan_done(&CT.nc, MT_NET_OK);
    CHECK(ct_parse(&rc, &o, &s, &c) == 0 && !mt_tlv_find_ctx(&o, 2) && !mt_tlv_enter(&o));
    n = 0;
    while (!mt_tlv_next(&o)) {
        it = o;
        CHECK(!mt_tlv_enter(&it) && field_u(&it, 3, &v) && v == (uint64_t)(15 - n)); /* strongest first */
        n++;
    }
    CHECK(n == MT_NETCOMM_MAX_SCAN_RESULTS);
    /* the platform's failure statuses: no result list, status recorded, breadcrumb untouched */
    im_scan(S_CASE1, 63, NULL, 77);
    mt_netcomm_scan_done(&CT.nc, MT_NET_NETWORK_NOT_FOUND);
    CHECK(ct_resp(1, MT_NET_NETWORK_NOT_FOUND) && ct_parse(&rc, &o, &s, &c) == 0 && mt_tlv_find_ctx(&o, 2) != MT_OK);
    CHECK(rd_u(NC, 5, MT_NET_NETWORK_NOT_FOUND) && rd_u(GC, 0, 33));
    /* the port cannot start a scan: answered at once */
    CT.nf.scan_err = MT_ERR_IO;
    n = CT.holds;
    im_scan(S_CASE1, 64, NULL, -1);
    CHECK(CT.holds == n && ct_resp(1, MT_NET_OTHER_CONNECTION_FAILURE) && CT.nc.op.kind == 0);
    CT.nf.scan_err = MT_OK;
    /* an SSID over 32 bytes */
    {
        uint8_t long33[33];
        mt_tlv_wr *w = req();
        memset(long33, 'a', sizeof long33);
        mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(long33, 33));
        im_inv(S_CASE1, 65, NC, 0, w, false);
        CHECK(ct_status(MT_IM_CONSTRAINT_ERROR, -1) && CT.nc.op.kind == 0);
    }
    /* poll gives up on a scan that never finishes */
    im_scan(S_CASE1, 66, NULL, -1);
    n = CT.nsent;
    F.now += 11999;
    CHECK(mt_netcomm_poll(&CT.nc) == 1 && CT.nsent == n);
    F.now += 1;
    CHECK(mt_netcomm_poll(&CT.nc) == UINT32_MAX && CT.nsent == n + 1 && ct_resp(1, MT_NET_UNKNOWN_ERROR) && CT.nc.op.kind == 0);
    /* a controller whose session closes loses its answer; the module frees itself at the deadline */
    im_scan(S_CASE1, 67, NULL, -1);
    n = CT.nsent;
    mt_im_on_session_closed(&CT.im, S_CASE1);
    mt_netcomm_scan_done(&CT.nc, MT_NET_OK);
    CHECK(CT.nsent == n && CT.nc.op.kind == 0);
    /* without an IM to answer through (no subscriptions wired), the deferred commands refuse */
    F.dm.im = NULL;
    {
        mt_tlv_wr *w = req();
        mt_tlv_put_bytes(w, mt_tlv_ctx(0), sp("home"));
        CHECK(invoke(S_CASE1, NC, 6, w, &rc, NULL) == MT_IM_FAILSAFE_REQUIRED);
        CHECK(invoke(S_CASE1, NC, 0, req(), &rc, NULL) == MT_IM_FAILURE && CT.nc.op.kind == 0);
    }
}

/* ---- General Diagnostics ---- */

static void test_gendiag(void)
{
    mt_tlv_rd r, x, l;
    uint64_t v;
    bool b;
    mt_span sb;
    uint32_t rc, dv0, dv1;
    mt_tlv_rd o;
    mt_gendiag g;
    mt_gendiag_cfg c;
    ct_init(true);
    CHECK(rd_u(GD, 0xFFFD, 2) && rd_u(GD, 0xFFFC, 0) && rd_u(GD, 1, 7) && rd_u(GD, 4, MT_BOOT_SW_WATCHDOG));
    CHECK(list_len(S_PASE, false, GD, 0xFFF9) == 2 && list_len(S_PASE, false, GD, 0xFFF8) == 1);
    CHECK(list_len(S_PASE, false, GD, 0xFFFB) == 5 + 5);
    /* UpTime accumulates 32-bit clock deltas (the clock starts near the wrap) */
    CHECK(rd_u(GD, 2, 0));
    CT.gf.ms += 5500;
    CHECK(rd_u(GD, 2, 5));
    CT.gf.ms += 0x2000; /* crosses 2^32 */
    CHECK(rd_u(GD, 2, 5 + 8));
    mt_gendiag_tick(&CT.gd);
    CT.gf.ms += 1000;
    CHECK(rd_u(GD, 2, 5 + 8 + 1) || rd_u(GD, 2, 5 + 8 + 2)); /* 5500 + 8192 + 1000 ms = 14 s (rounds down) */
    /* TestEventTriggersEnabled */
    CHECK(rd(S_PASE, false, GD, 8, 0, &r) == MT_OK && !mt_tlv_get_bool(&r, &b) && b);
    c = CT.gd.c;
    c.enable_key = NULL;
    CHECK(mt_gendiag_init(&g, &c) == MT_OK);
    c.now_ms = NULL;
    CHECK(mt_gendiag_init(&g, &c) == MT_ERR_INVALID);
    /* NetworkInterfaces: empty without an interface, then one Wi-Fi interface */
    CHECK(list_len(S_PASE, false, GD, 0) == 0);
    CT.gf.have_iface = true;
    memcpy(CT.gf.iface.name, "wlan0", 6);
    CT.gf.iface.operational = true;
    CT.gf.iface.hw_len = 6;
    memcpy(CT.gf.iface.hw, "\x18\xde\x50\xd6\x1f\x61", 6);
    CT.gf.iface.n4 = 1;
    memcpy(CT.gf.iface.v4[0], "\xc0\xa8\x03\x0b", 4);
    CT.gf.iface.n6 = 2;
    CT.gf.iface.v6[0][0] = 0xFE; CT.gf.iface.v6[0][1] = 0x80;
    CT.gf.iface.v6[1][0] = 0xFD;
    CT.gf.iface.type = MT_IFACE_WIFI;
    CHECK(list_len(S_PASE, false, GD, 0) == 1 && rd(S_PASE, false, GD, 0, 0, &r) == MT_OK);
    x = r;
    CHECK(!mt_tlv_enter(&x));
    {
        mt_tlv_rd y = x;
        CHECK(!mt_tlv_find_ctx(&y, 0) && !mt_tlv_get_utf8(&y, &sb) && span_eq(sb, sp("wlan0")));
    }
    CHECK(field_u(&x, 7, &v) && v == MT_IFACE_WIFI && field_b(&x, 4, &sb) && sb.len == 6 && sb.p[0] == 0x18);
    {
        mt_tlv_rd y = x;
        CHECK(!mt_tlv_find_ctx(&y, 1) && !mt_tlv_get_bool(&y, &b) && b);
        y = x; CHECK(!mt_tlv_find_ctx(&y, 2) && y.type == MT_TLV_NULL);
        y = x; CHECK(!mt_tlv_find_ctx(&y, 3) && y.type == MT_TLV_NULL);
        y = x; CHECK(!mt_tlv_find_ctx(&y, 5) && !mt_tlv_enter(&y) && !mt_tlv_next(&y) && !mt_tlv_get_bytes(&y, &sb) &&
                     sb.len == 4 && sb.p[3] == 0x0b && mt_tlv_next(&y) != MT_OK);
        y = x; CHECK(!mt_tlv_find_ctx(&y, 6) && !mt_tlv_enter(&y));
        l = y;
        CHECK(!mt_tlv_next(&l) && !mt_tlv_get_bytes(&l, &sb) && sb.len == 16 && sb.p[0] == 0xFE &&
              !mt_tlv_next(&l) && !mt_tlv_get_bytes(&l, &sb) && sb.p[0] == 0xFD && mt_tlv_next(&l) != MT_OK);
    }
    CHECK(mt_dm_dataver(&F.dm, 0, GD, &dv0));
    mt_gendiag_iface_changed(&CT.gd, &F.dm);
    CHECK(mt_dm_dataver(&F.dm, 0, GD, &dv1) && dv1 == dv0 + 1);
    /* TestEventTrigger: Manage; a missing/short/wrong key or no configured key is ConstraintError */
    {
        mt_tlv_wr *w;
        uint8_t key[16];
        memset(key, 0xA5, sizeof key);
        w = req();
        mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(key, 16));
        mt_tlv_put_u(w, mt_tlv_ctx(1), 0x0123456789ull);
        CHECK(invoke(S_CASE1, GD, 0, w, &rc, NULL) == MT_IM_SUCCESS && CT.gf.triggers == 1 && CT.gf.last_trigger == 0x0123456789ull);
        w = req();
        mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(key, 15));
        mt_tlv_put_u(w, mt_tlv_ctx(1), 1);
        CHECK(invoke(S_CASE1, GD, 0, w, &rc, NULL) == MT_IM_CONSTRAINT_ERROR);
        key[15] ^= 1;
        w = req();
        mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(key, 16));
        mt_tlv_put_u(w, mt_tlv_ctx(1), 1);
        CHECK(invoke(S_CASE1, GD, 0, w, &rc, NULL) == MT_IM_CONSTRAINT_ERROR && CT.gf.triggers == 1);
        key[15] ^= 1;
        w = req();
        mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(key, 16));
        CHECK(invoke(S_CASE1, GD, 0, w, &rc, NULL) == MT_IM_INVALID_COMMAND); /* EventTrigger missing */
        CT.gf.trigger_err = MT_ERR_INVALID;
        w = req();
        mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(key, 16));
        mt_tlv_put_u(w, mt_tlv_ctx(1), 2);
        CHECK(invoke(S_CASE1, GD, 0, w, &rc, NULL) == MT_IM_INVALID_COMMAND && CT.gf.triggers == 2);
        /* no key configured (all zero): disabled, whatever the controller sends */
        memset(CT.gf.key, 0, sizeof CT.gf.key);
        CHECK(rd(S_PASE, false, GD, 8, 0, &r) == MT_OK && !mt_tlv_get_bool(&r, &b) && !b);
        memset(key, 0, sizeof key);
        w = req();
        mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of(key, 16));
        mt_tlv_put_u(w, mt_tlv_ctx(1), 1);
        CHECK(invoke(S_CASE1, GD, 0, w, &rc, NULL) == MT_IM_CONSTRAINT_ERROR && CT.gf.triggers == 2);
    }
    /* TimeSnapshot: system time in ms since boot, no POSIX time */
    CT.gf.ms += 1000;
    CHECK(invoke(S_CASE1, GD, 1, NULL, &rc, &o) == MT_IM_SUCCESS && rc == 2 && field_u(&o, 0, &v) && v == 5500u + 0x2000u + 1000u + 1000u);
    CHECK(!mt_tlv_find_ctx(&o, 1) && o.type == MT_TLV_NULL);
    CHECK(invoke(S_CASE1, GD, 2, NULL, &rc, &o) == MT_IM_UNSUPPORTED_COMMAND);
}

/* ---- Administrator Commissioning ---- */

static mt_im_status ocw(int sid, unsigned timeout, size_t verifier_len, unsigned disc, uint32_t iter, size_t salt_len)
{
    static uint8_t vf[200], salt[64];
    mt_tlv_wr *w = req();
    uint32_t rc;
    for (size_t i = 0; i < sizeof vf; i++) vf[i] = (uint8_t)(i + 1);
    for (size_t i = 0; i < sizeof salt; i++) salt[i] = (uint8_t)(0x80 + i);
    mt_tlv_put_u(w, mt_tlv_ctx(0), timeout);
    mt_tlv_put_bytes(w, mt_tlv_ctx(1), mt_span_of(vf, verifier_len));
    mt_tlv_put_u(w, mt_tlv_ctx(2), disc);
    mt_tlv_put_u(w, mt_tlv_ctx(3), iter);
    mt_tlv_put_bytes(w, mt_tlv_ctx(4), mt_span_of(salt, salt_len));
    return invoke(sid, AD, 0, w, &rc, NULL);
}
#define PAKE MT_IM_CST(MT_ADMIN_PAKE_PARAMETER_ERROR)
#define ABUSY MT_IM_CST(MT_ADMIN_BUSY)
#define ANOTOPEN MT_IM_CST(MT_ADMIN_WINDOW_NOT_OPEN)

static void test_admincomm(void)
{
    uint32_t rc, dv0, dv1;
    mt_admin a;
    mt_admin_cfg ac;
    mt_admin_ops bad = AOPS;
    ct_init(true);
    CHECK(rd_u(AD, 0xFFFD, 1) && rd_u(AD, 0xFFFC, 0));
    CHECK(list_len(S_PASE, false, AD, 0xFFF9) == 2 && list_len(S_PASE, false, AD, 0xFFF8) == 0);
    CHECK(rd_u(AD, 0, MT_WINDOW_NOT_OPEN) && is_null(AD, 1) && is_null(AD, 2));
    /* revoke with nothing open: WindowNotOpen */
    CHECK(invoke(S_CASE1, AD, 2, NULL, &rc, NULL) == ANOTOPEN && CT.af.closes == 0);
    /* parameter checks, in chip's order */
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 10000, 32) == MT_IM_SUCCESS && CT.af.opens == 1);
    CHECK(invoke(S_CASE1, AD, 2, NULL, &rc, NULL) == MT_IM_SUCCESS && CT.af.closes == 1);
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 999, 32) == PAKE);
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 100001, 32) == PAKE);
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 1000, 16) == MT_IM_SUCCESS);
    CHECK(invoke(S_CASE1, AD, 2, NULL, &rc, NULL) == MT_IM_SUCCESS);
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 100000, 32) == MT_IM_SUCCESS);
    CHECK(invoke(S_CASE1, AD, 2, NULL, &rc, NULL) == MT_IM_SUCCESS);
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 10000, 15) == PAKE);
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 10000, 33) == PAKE);
    CHECK(ocw(S_CASE1, 179, 97, 0xABC, 10000, 32) == MT_IM_INVALID_COMMAND);
    CHECK(ocw(S_CASE1, 901, 97, 0xABC, 10000, 32) == MT_IM_INVALID_COMMAND);
    CHECK(ocw(S_CASE1, 300, 97, 0x1000, 10000, 32) == MT_IM_INVALID_COMMAND);
    CHECK(ocw(S_CASE1, 300, 96, 0xABC, 10000, 32) == PAKE);
    CHECK(ocw(S_CASE1, 300, 98, 0xABC, 10000, 32) == PAKE);
    CHECK(ocw(S_CASE1, 179, 97, 0xABC, 999, 32) == PAKE); /* PBKDF parameters before the timeout */
    CHECK(ocw(S_CASE1, 180, 97, 0, 1000, 16) == MT_IM_SUCCESS);   /* the limits themselves */
    CHECK(invoke(S_CASE1, AD, 2, NULL, &rc, NULL) == MT_IM_SUCCESS);
    CHECK(ocw(S_CASE1, 900, 97, 0xFFF, 1000, 16) == MT_IM_SUCCESS);
    CHECK(invoke(S_CASE1, AD, 2, NULL, &rc, NULL) == MT_IM_SUCCESS);
    {   /* missing field */
        mt_tlv_wr *w = req();
        mt_tlv_put_u(w, mt_tlv_ctx(0), 300);
        CHECK(invoke(S_CASE1, AD, 0, w, &rc, NULL) == MT_IM_INVALID_COMMAND);
    }
    /* a PASE session that was not adopted has no fabric to be the administrator of */
    fx_session(S_CASE_OTHER, MT_IM_AUTH_PASE, 0, 0);
    {
        int opens = CT.af.opens;
        CHECK(ocw(S_CASE_OTHER, 300, 97, 0xABC, 10000, 32) == PAKE && CT.af.opens == opens);
    }
    /* the port refuses: PAKEParameterError, nothing recorded */
    {
        int opens = CT.af.opens;
        CT.af.open_err = MT_ERR_IO;
        CHECK(ocw(S_CASE1, 300, 97, 0xABC, 10000, 32) == PAKE && CT.af.opens == opens + 1 && CT.ad.fabric == 0);
        CT.af.open_err = MT_OK;
    }
    /* fail-safe armed: Busy, ahead of the parameter checks */
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 10000, 32) == ABUSY && ocw(S_CASE1, 10, 97, 0xABC, 5, 3) == ABUSY);
    CHECK(arm(S_CASE1, 0, 0) == MT_COMM_OK);
    /* the happy path: the port got the verifier halves, salt copy, fabric and vendor id */
    CT.af.opens = 0;
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 10000, 32) == MT_IM_SUCCESS && CT.af.opens == 1);
    {
        const mt_admin_window *w = &CT.af.w;
        bool ok = w->timeout_s == 300 && w->discriminator == 0xABC && w->iterations == 10000 && w->fabric == 1 &&
                  w->vendor_id == 0xFFF1 && CT.af.salt_len == 32 && CT.af.salt[0] == 0x80 && CT.af.salt[31] == 0x9F;
        for (unsigned i = 0; i < 32; i++) ok = ok && w->w0[i] == i + 1;
        for (unsigned i = 0; i < 65; i++) ok = ok && w->l[i] == 33 + i;
        CHECK(ok);
    }
    CHECK(rd_u(AD, 0, MT_WINDOW_ENHANCED) && rd_u(AD, 1, 1) && rd_u(AD, 2, 0xFFF1));
    CHECK(mt_dm_dataver(&F.dm, 0, AD, &dv0));
    /* a window is open: Busy */
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 10000, 32) == ABUSY);
    /* revoking with an armed fail-safe ends the fail-safe first (chip) and closes the window */
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    CHECK(invoke(S_CASE1, AD, 2, NULL, &rc, NULL) == MT_IM_SUCCESS && !mt_root_failsafe_armed(&F.r) && CT.af.closes >= 1);
    CHECK(rd_u(AD, 0, MT_WINDOW_NOT_OPEN) && is_null(AD, 1) && is_null(AD, 2));
    CHECK(mt_dm_dataver(&F.dm, 0, AD, &dv1) && dv1 != dv0);
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    CHECK(invoke(S_CASE1, AD, 2, NULL, &rc, NULL) == ANOTOPEN && !mt_root_failsafe_armed(&F.r));
    /* the node's own windows: WindowStatus WindowNotOpen and no administrator (chip v1.3
     * CommissioningWindowStatusForCluster), the opener is forgotten when the window ends */
    CT.af.status = MT_WINDOW_BASIC;
    CHECK(rd_u(AD, 0, MT_WINDOW_NOT_OPEN) && is_null(AD, 1) && is_null(AD, 2));
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 10000, 32) == ABUSY);
    CT.af.status = MT_WINDOW_NOT_OPEN;
    mt_admin_window_changed(&CT.ad);
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 10000, 32) == MT_IM_SUCCESS && CT.ad.fabric == 1);
    CT.af.status = MT_WINDOW_NOT_OPEN; /* the window timed out by itself */
    mt_admin_window_changed(&CT.ad);
    CHECK(CT.ad.fabric == 0 && is_null(AD, 1));
    /* a fabric removal closes the window its administrator opened, not another one's */
    CHECK(ocw(S_CASE1, 300, 97, 0xABC, 10000, 32) == MT_IM_SUCCESS);
    {
        int closes = CT.af.closes;
        mt_admin_fabric_removed(&CT.ad, 2);
        mt_admin_fabric_removed(&CT.ad, 0);
        CHECK(CT.af.closes == closes && CT.af.status == MT_WINDOW_ENHANCED);
        mt_admin_fabric_removed(&CT.ad, 1);
        CHECK(CT.af.closes == closes + 1 && CT.af.status == MT_WINDOW_NOT_OPEN && CT.ad.fabric == 0);
    }
    /* both commands are timed (11.19.8): an untimed request through the IM needs a timed interaction */
    {
        mt_tlv_wr *w = req();
        im_inv(S_CASE1, 90, AD, 2, NULL, false);
        CHECK(ct_status(MT_IM_NEEDS_TIMED_INTERACTION, -1));
        (void)w;
        im_inv(S_CASE1, 91, AD, 0, req(), false);
        CHECK(ct_status(MT_IM_NEEDS_TIMED_INTERACTION, -1));
    }
    /* init checks */
    ac = (mt_admin_cfg){ &AOPS, &CT.af, &F.r };
    CHECK(mt_admin_init(&a, &ac) == MT_OK);
    ac.root = NULL;
    CHECK(mt_admin_init(&a, &ac) == MT_ERR_INVALID);
    ac.root = &F.r; bad.close = NULL; ac.ops = &bad;
    CHECK(mt_admin_init(&a, &ac) == MT_ERR_INVALID);
    ac.ops = NULL;
    CHECK(mt_admin_init(&a, &ac) == MT_ERR_INVALID);
}


/* ---- malformed command fields: every command of the root clusters, through the IM engine ----
 * Variants: no fields, every field 0..7 as an array, as a string, as a negative int, as null, as a nested struct,
 * and fields given twice. Required fields of the wrong type must be refused with INVALID_COMMAND (spec 8.10.4.2
 * "...data type mismatch") or CONSTRAINT_ERROR, and nothing may crash or trip ASan/UBSan. Run from an armed
 * PASE session (the commissioning paths) and from a CASE Administer session (the commissioned paths). */
typedef struct { uint32_t cl, cmd; bool f0_required; } sweep_cmd;
static const sweep_cmd SWEEP[] = {
    { GC, 0, true }, { GC, 2, true }, { GC, 4, false },
    { OC, 0, true }, { OC, 2, true }, { OC, 4, true }, { OC, 6, true }, { OC, 7, true }, { OC, 9, true },
    { OC, 10, true }, { OC, 11, true },
    { GKM, 0, true }, { GKM, 1, true }, { GKM, 3, true }, { GKM, 4, false },
    { MT_NETCOMM_CLUSTER_ID, 2, true }, { MT_NETCOMM_CLUSTER_ID, 4, true }, { MT_NETCOMM_CLUSTER_ID, 6, true },
    { MT_NETCOMM_CLUSTER_ID, 8, true },
    { MT_GENDIAG_CLUSTER_ID, 0, true }, { MT_GENDIAG_CLUSTER_ID, 1, false },
    { MT_ADMIN_CLUSTER_ID, 0, true }, { MT_ADMIN_CLUSTER_ID, 2, false }, { MT_TIMESYNC_CLUSTER_ID, 0, true },
    /* last: a valid ScanNetworks (no fields) defers and keeps the cluster BUSY for the rest of the run */
    { MT_NETCOMM_CLUSTER_ID, 0, false },
};
enum { V_NONE, V_ARRAY, V_STRING, V_NEG, V_NULL, V_STRUCT, V_TWICE, V_N };
static void sweep_fields(mt_tlv_wr *w, int v)
{
    for (uint8_t t = 0; t < 8; t++) {
        switch (v) {
        case V_ARRAY: mt_tlv_start(w, mt_tlv_ctx(t), MT_TLV_ARRAY); mt_tlv_put_u(w, mt_tlv_anon(), 1); mt_tlv_end(w); break;
        case V_STRING: mt_tlv_put_utf8(w, mt_tlv_ctx(t), "x", 1); break;
        case V_NEG: mt_tlv_put_i(w, mt_tlv_ctx(t), -1); break;
        case V_NULL: mt_tlv_put_null(w, mt_tlv_ctx(t)); break;
        case V_STRUCT:
            mt_tlv_start(w, mt_tlv_ctx(t), MT_TLV_STRUCT);
            mt_tlv_start(w, mt_tlv_ctx(0), MT_TLV_STRUCT); mt_tlv_put_u(w, mt_tlv_ctx(0), 1); mt_tlv_end(w);
            mt_tlv_end(w);
            break;
        case V_TWICE: mt_tlv_put_u(w, mt_tlv_ctx(t), 1); mt_tlv_put_u(w, mt_tlv_ctx(t), 2); break;
        default: return;
        }
    }
}
static void sweep_run(int sid)
{
    unsigned nfab = (unsigned)mt_fabric_count(&F.t);
    for (size_t i = 0; i < sizeof SWEEP / sizeof SWEEP[0]; i++)
        for (int v = 0; v < V_N; v++) {
            mt_tlv_wr *w = req();
            uint32_t rc = 0;
            mt_tlv_rd o;
            int st = -9, cst = -9, k;
            sweep_fields(w, v);
            uint16_t exch = (uint16_t)(0x4000 + i * V_N + v);
            uint8_t treq[16];
            mt_tlv_wr tw;
            mt_im_subject su = subj(sid);
            bool timed = SWEEP[i].cl == MT_ADMIN_CLUSTER_ID; /* its commands are timed (11.19.8) */
            if (timed) {
                mt_tlv_wr_init(&tw, mt_buf_of(treq, sizeof treq));
                mt_tlv_start(&tw, mt_tlv_anon(), MT_TLV_STRUCT);
                mt_tlv_put_u(&tw, mt_tlv_ctx(0), 5000);
                mt_tlv_put_u(&tw, mt_tlv_ctx(0xFF), 11);
                mt_tlv_end(&tw);
                mt_im_on_msg(&CT.im, &su, exch, MT_IM_OP_TIMED, mt_tlv_wr_span(&tw));
            }
            CT.last.op = 0;
            im_inv(sid, exch, SWEEP[i].cl, SWEEP[i].cmd, w, timed);
            mt_im_poll(&CT.im);
            if (CT.last.op == 0) continue; /* deferred (connect/scan): answered later or never; no crash is the test */
            k = ct_parse(&rc, &o, &st, &cst);
            CHECK(k == 0 || k == 1);
            /* Only RemoveFabric with FabricIndex given twice (1, then 2) may remove one: a struct with a repeated
             * tag is malformed TLV (spec Appendix A, structures: member tags are unique); we take the first
             * occurrence (the session's own fabric 1, a valid self-removal), chip's decoders the last. */
            if (mt_fabric_count(&F.t) != nfab) {
                CHECK(SWEEP[i].cl == OC && SWEEP[i].cmd == 10 && v == V_TWICE);
                nfab = (unsigned)mt_fabric_count(&F.t);
            }
            /* a wrong-typed or missing required field never succeeds */
            if (v != V_NONE && v != V_NULL && v != V_TWICE && SWEEP[i].f0_required && k == 1) {
                if (st == 0) printf("  sweep 0x%lx/%lu v%d: SUCCESS\n", (unsigned long)SWEEP[i].cl,
                                    (unsigned long)SWEEP[i].cmd, v);
                CHECK(st != 0);
            }
            if (SWEEP[i].cl == OC && SWEEP[i].cmd == 9 && v == V_STRING) continue; /* Label "x" is valid */
            if (SWEEP[i].f0_required && (v == V_ARRAY || v == V_STRING || v == V_STRUCT) && k == 1 &&
                !(st == MT_IM_INVALID_COMMAND || st == MT_IM_CONSTRAINT_ERROR || st == MT_IM_FAILURE ||
                  st == MT_IM_UNSUPPORTED_ACCESS || st == MT_IM_UNSUPPORTED_COMMAND || st == 0x01 /* FAILURE */)) {
                printf("  sweep 0x%lx/%lu v%d: status 0x%02x\n", (unsigned long)SWEEP[i].cl,
                       (unsigned long)SWEEP[i].cmd, v, st);
                CHECK(false);
            }
            if (SWEEP[i].f0_required && v == V_NONE && k == 1 && st == 0) {
                printf("  sweep 0x%lx/%lu no fields: SUCCESS\n", (unsigned long)SWEEP[i].cl,
                       (unsigned long)SWEEP[i].cmd);
                CHECK(false);
            }
            if (k == 0 && SWEEP[i].f0_required && (v == V_ARRAY || v == V_STRING || v == V_STRUCT || v == V_NONE))
                printf("  sweep 0x%lx/%lu v%d: response 0x%lx\n", (unsigned long)SWEEP[i].cl,
                       (unsigned long)SWEEP[i].cmd, v, (unsigned long)rc);
        }
}
static void test_malformed_sweep(void)
{
    ct_init(false);
    CHECK(arm(S_PASE, 120, 1) == MT_COMM_OK);
    sweep_run(S_PASE);
    ct_init(true);
    sweep_run(S_CASE1);
}

/* CommissioningComplete persists the staged Wi-Fi before the fabric image (so a power cut never leaves a
 * fabric without a network). When a step fails, the answer is FAILURE, the fail-safe stays armed and nothing stays
 * persisted: a failed fabric commit restores the previous network record, so the eventual expiry brings Network
 * Commissioning back to its state before the fail-safe was armed (11.10.7.2), and a retry commits both again. */
static void prep_new_fabric_with_wifi(void)
{
    mt_tlv_rd o;
    uint8_t idx = 0;
    ct_init(false);
    CT.nf.has_saved = true; CT.nf.saved_len = 3; memcpy(CT.nf.saved_ssid, "old", 3);
    CT.nf.saved_cred_len = 8; memcpy(CT.nf.saved_cred, "oldpass1", 8);
    CHECK(arm(S_PASE, 60, 1) == MT_COMM_OK);
    CHECK(csr(S_PASE, "Node01_02", k_Node01_02_priv, -1, &o) == MT_IM_SUCCESS);
    CHECK(add_trc(S_PASE, "Root01") == MT_IM_SUCCESS);
    CT.nc.c.replace_when_full = true;
    CHECK(add_noc(S_PASE, "Node01_02", NULL, ADMIN1, &idx) == MT_NOC_OK && idx == 1);
    CHECK(add_wifi(S_PASE, sp("home"), sp("password1"), -1, NULL, NULL) == MT_NET_OK);
    fx_session(S_CASE1, MT_IM_AUTH_CASE, 1, ADMIN1);
}

static bool saved_is(const char *ssid, const char *cred)
{
    return CT.nf.has_saved && CT.nf.saved_len == strlen(ssid) && !memcmp(CT.nf.saved_ssid, ssid, CT.nf.saved_len) &&
           CT.nf.saved_cred_len == strlen(cred) && !memcmp(CT.nf.saved_cred, cred, CT.nf.saved_cred_len);
}

static void test_complete_atomicity(void)
{
    mt_im_status st;
    ct_init(true);
    stage_home();
    CHECK(complete(S_CASE1, &st) == MT_COMM_OK && CT.nf.saves == 1);
    CHECK(arm(S_CASE1, 60, 1) == MT_COMM_OK);
    CHECK(add_wifi(S_CASE1, sp("home"), sp("password3"), -1, NULL, NULL) == MT_NET_OK);
    F.commit_err = MT_ERR_IO; /* the node's commit step runs first (before any flash write) and fails */
    CHECK(complete(S_CASE1, &st) == -1 && st == MT_IM_FAILURE && mt_root_failsafe_armed(&F.r));
    F.commit_err = MT_OK;
    mt_root_failsafe_expire(&F.r);
    CHECK(CT.nf.saves == 1); /* nothing persisted */
    CHECK(CT.nf.saved_cred_len == 9 && !memcmp(CT.nf.saved_cred, "password1", 9));

    /* the fabric commit fails after the Wi-Fi save: the old record comes back, the change stays staged */
    prep_new_fabric_with_wifi();
    F.kv.finish_err = MT_ERR_IO;
    CHECK(complete(S_CASE1, &st) == -1 && st == MT_IM_FAILURE && mt_root_failsafe_armed(&F.r));
    F.kv.finish_err = MT_OK;
    CHECK(CT.nf.saves == 1 && CT.nf.restores == 1 && saved_is("old", "oldpass1") && CT.nc.stage.kind == 1);
    /* ... the expiry then leaves the previous network as it was */
    mt_root_failsafe_expire(&F.r);
    CHECK(saved_is("old", "oldpass1") && CT.nc.stage.kind == 0 && net_is("old", false) && mt_fabric_count(&F.t) == 0);
    /* ... or a retry commits both */
    prep_new_fabric_with_wifi();
    F.kv.finish_err = MT_ERR_IO;
    CHECK(complete(S_CASE1, &st) == -1 && st == MT_IM_FAILURE);
    F.kv.finish_err = MT_OK;
    CHECK(complete(S_CASE1, &st) == MT_COMM_OK && CT.nf.saves == 2 && saved_is("home", "password1"));
    CHECK(mt_fabric_count(&F.t) == 1 && CT.nc.stage.kind == 0 && !mt_root_failsafe_armed(&F.r));
    mt_root_failsafe_expire(&F.r);
    CHECK(saved_is("home", "password1") && CT.nf.restores == 1);
}

/* An ACL list written the way chip's WriteClient encodes a list too big for one IB: replace with [] and then one
 * append per entry (spec 8.7.3.3), in one message or in chunks. The empty list drops fabric 1's Administer entry;
 * the appends must still pass, as chip caches the last granted check per path for the whole write interaction
 * (WriteHandler::ACLCheckCacheHit, v1.3 ember-compatibility-functions.cpp WriteSingleClusterData). Without it the
 * admin locks itself out of its own fabric. */
static size_t acl_wr_msg(uint8_t *buf, size_t cap, int first_ib, int n_ib, bool more)
{
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, mt_buf_of(buf, cap));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bool(&w, mt_tlv_ctx(0), false);
    mt_tlv_put_bool(&w, mt_tlv_ctx(1), false);
    mt_tlv_start(&w, mt_tlv_ctx(2), MT_TLV_ARRAY);
    for (int ib = first_ib; ib < first_ib + n_ib; ib++) {
        mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
        mt_tlv_start(&w, mt_tlv_ctx(1), MT_TLV_LIST);
        mt_tlv_put_u(&w, mt_tlv_ctx(2), 0);
        mt_tlv_put_u(&w, mt_tlv_ctx(3), ACL);
        mt_tlv_put_u(&w, mt_tlv_ctx(4), 0);
        if (ib) mt_tlv_put_null(&w, mt_tlv_ctx(5));
        mt_tlv_end(&w);
        if (ib == 0) {
            mt_tlv_start(&w, mt_tlv_ctx(2), MT_TLV_ARRAY);
            mt_tlv_end(&w);
        } else {
            mt_tlv_wr e;
            uint8_t eb[96];
            mt_tlv_wr_init(&e, mt_buf_of(eb, sizeof eb));
            put_entry(&e, ib == 1 ? MT_ACL_PRIV_ADMINISTER : MT_ACL_PRIV_VIEW, MT_ACL_AUTH_CASE,
                      ib == 1 ? ADMIN1 : 0x3344, 1);
            /* re-tag the anonymous entry struct as Data (context 2) */
            mt_span es = mt_tlv_wr_span(&e);
            mt_tlv_start(&w, mt_tlv_ctx(2), MT_TLV_STRUCT);
            mt_tlv_put_raw(&w, mt_span_of(es.p + 1, es.len - 2));
            mt_tlv_end(&w);
        }
        mt_tlv_end(&w);
    }
    mt_tlv_end(&w);
    if (more) mt_tlv_put_bool(&w, mt_tlv_ctx(3), true);
    mt_tlv_put_u(&w, mt_tlv_ctx(0xFF), 11);
    mt_tlv_end(&w);
    return mt_tlv_wr_span(&w).len;
}
static void test_acl_list_write_in_parts(void)
{
    static uint8_t m[600];
    for (int chunked = 0; chunked < 2; chunked++) {
        mt_im_subject su;
        ct_init(true);
        su = subj(S_CASE1);
        if (!chunked) {
            mt_im_on_msg(&CT.im, &su, 300, MT_IM_OP_WRITE, mt_span_of(m, acl_wr_msg(m, sizeof m, 0, 3, false)));
        } else {
            mt_im_on_msg(&CT.im, &su, 301, MT_IM_OP_WRITE, mt_span_of(m, acl_wr_msg(m, sizeof m, 0, 2, true)));
            CHECK(CT.last.op == MT_IM_OP_WRITE_RESP);
            mt_im_on_msg(&CT.im, &su, 301, MT_IM_OP_WRITE, mt_span_of(m, acl_wr_msg(m, sizeof m, 2, 1, false)));
        }
        CHECK(CT.last.op == MT_IM_OP_WRITE_RESP);
        if (list_len(S_CASE1, true, ACL, 0) != 2)
            printf("  acl in parts (%s): %u entries\n", chunked ? "chunked" : "one message", list_len(S_CASE1, true, ACL, 0));
        CHECK(list_len(S_CASE1, true, ACL, 0) == 2);
        CHECK(mt_root_access(&F.r, &su, 0, ACL, MT_ACL_PRIV_ADMINISTER));
    }
}

static void test_ctl(void)
{
    test_netcomm_attrs();
    test_netcomm_staging();
    test_netcomm_connect();
    test_netcomm_scan();
    test_gendiag();
    test_admincomm();
    test_malformed_sweep();
    test_complete_atomicity();
    test_acl_list_write_in_parts();
}
