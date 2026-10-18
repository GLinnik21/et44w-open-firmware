/* Host tests for matter-thermostat. The endpoint is wired into a real matter-dm/matter-im node (a root
 * endpoint with only the Descriptor, plus endpoint 1) and driven through the mt_im_dm boundary: attribute
 * enumeration, reads, writes, invokes, data versions and dirty marks. thermo is the real model.
 * Expected values come from the Matter 1.3 data model files (data_model/1.3 Thermostat, Identify,
 * device type Thermostat) and chip v1.3-branch thermostat-server.cpp, not from the implementation. */
#include <stdio.h>
#include <string.h>
#include "mt_thermostat.h"

static int g_fail, g_checks;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CTX(n) mt_tlv_ctx(n)
#define ANON mt_tlv_anon()

#define EP MT_THERMOSTAT_ENDPOINT
#define TS MT_THERMOSTAT_CLUSTER_ID
#define ID MT_IDENTIFY_CLUSTER_ID

/* ---------------- fixture ---------------- */

static thermo g_model;
static mt_thermostat g_t;
static mt_dm g_dm;
static mt_im g_im;
static uint32_t g_now;
static int g_on_write, g_ident_calls, g_ident_active;
static uint8_t g_tx[256];
static mt_dm_endpoint g_eps[3];
static mt_dm_node g_node;

static const mt_dm_devtype k_root_types[] = { { 0x16, 1 } };
static const mt_dm_cluster *const k_root_cl[] = { &mt_dm_descriptor };

static uint32_t f_now(void *ctx) { (void)ctx; return g_now; }
static void f_on_write(void *ctx) { (void)ctx; g_on_write++; }
static void f_on_identify(void *ctx, bool active) { (void)ctx; g_ident_calls++; g_ident_active = active; }

static mt_err p_send(void *ctx, uint16_t s, uint16_t *e, uint8_t op, mt_span p, bool x)
{
    (void)ctx; (void)s; (void)e; (void)op; (void)p; (void)x;
    return MT_OK;
}
static uint32_t p_now(void *ctx) { (void)ctx; return g_now; }
static const mt_im_ports k_ports = { p_send, p_now, NULL };

static bool f_access(void *ctx, const mt_im_subject *s, uint16_t ep, uint32_t cl, uint8_t priv)
{
    (void)ctx; (void)s; (void)ep; (void)cl; (void)priv;
    return true;
}

static const mt_im_subject k_subj = { 1, MT_IM_AUTH_CASE, 1, 0x1111 };

/* Raw DP2 values as the app configures thermo: holiday 0, smart 1, hold 2; DP3 heating = 1. */
static const thermo_cfg k_cfg = { .mode_hold = 2, .mode_smart = 1, .mode_holiday = 0, .state_heating = 1 };

static bool g_auto_mode;   /* setup(): mt_thermostat_cfg.auto_mode */

/* Fresh node. `reported`: the MCU has reported switch on, hold, 20.0 C target, 21.5 C current, idle. */
static void setup(bool reported, uint8_t identify_type)
{
    g_now = 1000; g_on_write = g_ident_calls = g_ident_active = 0;
    thermo_init(&g_model, &k_cfg);
    if (reported) {
        thermo_report(&g_model, THERMO_DP_SWITCH, 1, g_now);
        thermo_report(&g_model, THERMO_DP_MODE, 2, g_now);
        thermo_report(&g_model, THERMO_DP_STATE, 0, g_now);
        thermo_report(&g_model, THERMO_DP_SETPOINT, 200, g_now);
        thermo_report(&g_model, THERMO_DP_CURRENT, 215, g_now);
        thermo_report(&g_model, THERMO_DP_FAULT, 0, g_now);
    }
    mt_thermostat_cfg c = { .model = &g_model, .now_ms = f_now, .on_write = f_on_write,
                            .on_identify = f_on_identify, .identify_type = identify_type,
                            .auto_mode = g_auto_mode };
    CHECK(mt_thermostat_init(&g_t, &c) == MT_OK);
    g_eps[0] = (mt_dm_endpoint){ .id = 0, .n_types = 1, .n_clusters = 1, .types = k_root_types,
                                 .clusters = k_root_cl };
    uint8_t n = mt_thermostat_endpoint_count(&g_t);
    CHECK(n == (g_auto_mode ? 1 : 2));
    memcpy(&g_eps[1], mt_thermostat_endpoint(&g_t), n * sizeof g_eps[0]);   /* the node copies them like this */
    g_node = (mt_dm_node){ g_eps, (uint8_t)(1 + n) };
    mt_dm_cfg dc = { &g_node, &g_im, f_access, NULL, 0x1000 };
    CHECK(mt_dm_init(&g_dm, &dc) == MT_OK);
    mt_im_cfg ic = { &mt_dm_im, &g_dm, &k_ports, NULL, mt_buf_of(g_tx, sizeof g_tx), 1, 1 };
    mt_im_init(&g_im, &ic);
}

/* ---------------- helpers over the mt_im_dm boundary ---------------- */

static bool find_attr(uint16_t ep, uint32_t cl, uint32_t at, mt_im_attr *a)
{
    for (uint16_t i = 0; !mt_dm_im.attr_at(&g_dm, i, a); i++)
        if (a->endpoint == ep && a->cluster == cl && a->attr == at) return true;
    return false;
}

static uint32_t dataver(uint32_t cl)
{
    uint32_t v = 0;
    CHECK(mt_dm_dataver(&g_dm, EP, cl, &v));
    return v;
}

/* Reads item `item` of a scalar or list attribute into `buf`; positions `r` on the element. */
static mt_err read_item(uint16_t ep, uint32_t cl, uint32_t at, uint16_t item, uint8_t *buf, size_t cap, mt_tlv_rd *r)
{
    mt_im_attr a;
    mt_tlv_wr w;
    mt_span s;
    mt_im_rctx rc = { &k_subj, false };
    CHECK(find_attr(ep, cl, at, &a));
    mt_tlv_wr_init(&w, mt_buf_of(buf, cap));
    mt_err e = mt_dm_im.read(&g_dm, &rc, &a, item, &w, ANON);
    if (e) return e;
    CHECK(mt_tlv_wr_done(&w, &s) == MT_OK);
    mt_tlv_rd_init(r, s);
    CHECK(mt_tlv_next(r) == MT_OK);
    return MT_OK;
}

static int64_t rd_int(uint32_t cl, uint32_t at)
{
    uint8_t b[32];
    mt_tlv_rd r;
    int64_t v = -999999;
    CHECK(read_item(EP, cl, at, 0, b, sizeof b, &r) == MT_OK);
    CHECK(mt_tlv_get_i64(&r, &v) == MT_OK);
    return v;
}

static bool rd_null(uint32_t cl, uint32_t at)
{
    uint8_t b[32];
    mt_tlv_rd r;
    CHECK(read_item(EP, cl, at, 0, b, sizeof b, &r) == MT_OK);
    return r.type == MT_TLV_NULL;
}

/* A list of unsigned ids -> out[]; returns the count. */
static unsigned rd_list(uint16_t ep, uint32_t cl, uint32_t at, uint32_t *out, unsigned max)
{
    unsigned n = 0;
    for (;; n++) {
        uint8_t b[32];
        mt_tlv_rd r;
        mt_err e = read_item(ep, cl, at, (uint16_t)n, b, sizeof b, &r);
        if (e == MT_ERR_NOT_FOUND) return n;
        CHECK(e == MT_OK && n < max);
        if (e || n >= max) return n;
        uint64_t v = 0;
        CHECK(mt_tlv_get_u64(&r, &v) == MT_OK);
        out[n] = (uint32_t)v;
    }
}

static bool list_eq(const uint32_t *got, unsigned n, const uint32_t *want, unsigned wn)
{
    return n == wn && (n == 0 || !memcmp(got, want, n * sizeof *got));
}

#define LIST_IS(ep, cl, at, ...) do { \
        static const uint32_t w_[] = { __VA_ARGS__ }; uint32_t g_[32]; \
        unsigned n_ = rd_list(ep, cl, at, g_, 32); \
        CHECK(list_eq(g_, n_, w_, sizeof w_ / sizeof w_[0])); } while (0)

#define LIST_EMPTY(ep, cl, at) do { uint32_t g_[1]; CHECK(rd_list(ep, cl, at, g_, 0) == 0); } while (0)

enum { V_INT, V_UINT, V_NULL, V_BOOL, V_STR };
static uint8_t g_vbuf[32];

static mt_tlv_rd mk_val(int kind, int64_t v)
{
    mt_tlv_wr w;
    mt_tlv_rd r;
    mt_tlv_wr_init(&w, mt_buf_of(g_vbuf, sizeof g_vbuf));
    switch (kind) {
    case V_INT: mt_tlv_put_i(&w, ANON, v); break;
    case V_UINT: mt_tlv_put_u(&w, ANON, (uint64_t)v); break;
    case V_NULL: mt_tlv_put_null(&w, ANON); break;
    case V_BOOL: mt_tlv_put_bool(&w, ANON, v != 0); break;
    default: mt_tlv_put_utf8(&w, ANON, "x", 1); break;
    }
    mt_tlv_rd_init(&r, mt_tlv_wr_span(&w));
    CHECK(mt_tlv_next(&r) == MT_OK);
    return r;
}

static mt_im_status wr(uint32_t cl, uint32_t at, int kind, int64_t v)
{
    mt_im_attr a;
    mt_im_wctx wc = { &k_subj, false, false };
    mt_tlv_rd r = mk_val(kind, v);
    CHECK(find_attr(EP, cl, at, &a));
    return mt_dm_im.write(&g_dm, &wc, &a, MT_IM_WR_VALUE, &r);
}

/* Invoke with a struct of up to two context-tagged integers (-1000 = absent) or no fields. */
static uint8_t g_fbuf[48];
static mt_im_status inv(uint32_t cl, uint32_t cmd, bool with_struct, int64_t f0, int64_t f1, int kind1)
{
    mt_tlv_wr w;
    mt_tlv_rd r;
    uint8_t rb[32];
    mt_tlv_wr resp;
    uint32_t resp_cmd = MT_IM_WILD_ID;
    mt_im_cmd c = { EP, cl, cmd };
    mt_tlv_wr_init(&w, mt_buf_of(g_fbuf, sizeof g_fbuf));
    if (with_struct) {
        mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
        if (f0 != -1000) mt_tlv_put_i(&w, CTX(0), f0);
        if (f1 != -1000) {
            if (kind1 == V_BOOL) mt_tlv_put_bool(&w, CTX(1), true); else mt_tlv_put_i(&w, CTX(1), f1);
        }
        mt_tlv_end(&w);
    }
    mt_tlv_rd_init(&r, mt_tlv_wr_span(&w));
    mt_tlv_next(&r);   /* NONE when there is no struct */
    mt_tlv_wr_init(&resp, mt_buf_of(rb, sizeof rb));
    mt_im_status st = mt_dm_im.invoke(&g_dm, &k_subj, &c, &r, &resp, &resp_cmd);
    CHECK(resp_cmd == MT_IM_WILD_ID && resp.len == 0);   /* both commands answer DefaultSuccess */
    return st;
}

static uint32_t last_dirty_id(void)   /* the attribute of the newest mark (mt_im keeps a generation per path) */
{
    uint32_t best = 0, id = 0xDEAD;
    for (unsigned i = 0; i < MT_IM_N_DIRTY; i++)
        if (g_im.dirty[i].gen > best) { best = g_im.dirty[i].gen; id = g_im.dirty[i].path.id; }
    return id;
}

static void feed(uint8_t dp, int32_t v)
{
    thermo_report(&g_model, dp, v, g_now);
    mt_thermostat_sync(&g_t, &g_dm);
}

/* Marks + data version of the Thermostat cluster since a baseline. Endpoint 2 (Schedule) marks its own path
 * when the weekly program starts or stops; `sched` counts those so the totals stay exact. */
typedef struct { uint32_t gen, ver, sched; } mark_t;
static uint32_t sched_ver(void) { uint32_t v = 0; mt_dm_dataver(&g_dm, MT_SCHEDULE_ENDPOINT, MT_ONOFF_CLUSTER_ID, &v); return v; }
static mark_t mark(void) { mark_t m = { g_im.gen, dataver(TS), sched_ver() }; return m; }
static bool bumped(mark_t m, uint32_t n)
{
    return g_im.gen - m.gen - (sched_ver() - m.sched) == n && dataver(TS) - m.ver == n;
}

/* ---------------- tests ---------------- */

static void test_structure(void)
{
    setup(true, MT_IDENTIFY_TYPE_NONE + 2);
    mt_im_attr a;
    uint8_t b[32];
    mt_tlv_rd r;

    CHECK(mt_dm_check(&g_node) == MT_OK);
    CHECK(g_t.eps[0].id == 1 && g_t.eps[0].n_clusters == 3 && g_t.eps[0].n_clients == 0 && g_t.eps[0].n_types == 1);

    /* Descriptor: DeviceTypeList = [{0x0301, rev 3}], ServerList in table order, no client clusters. */
    CHECK(read_item(EP, MT_DM_CLUSTER_DESCRIPTOR, 0, 0, b, sizeof b, &r) == MT_OK && r.type == MT_TLV_STRUCT);
    CHECK(mt_tlv_enter(&r) == MT_OK && mt_tlv_next(&r) == MT_OK && mt_tlv_is_ctx(&r, 0));
    uint32_t v32 = 0;
    CHECK(mt_tlv_get_u32(&r, &v32) == MT_OK && v32 == 0x0301);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_is_ctx(&r, 1) && mt_tlv_get_u32(&r, &v32) == MT_OK && v32 == 3);
    CHECK(read_item(EP, MT_DM_CLUSTER_DESCRIPTOR, 0, 1, b, sizeof b, &r) == MT_ERR_NOT_FOUND);
    LIST_IS(EP, MT_DM_CLUSTER_DESCRIPTOR, 1, 0x03, 0x1D, 0x201);
    LIST_EMPTY(EP, MT_DM_CLUSTER_DESCRIPTOR, 2);      /* ClientList: empty */
    LIST_EMPTY(EP, MT_DM_CLUSTER_DESCRIPTOR, 3);      /* PartsList of a leaf endpoint: empty */
    LIST_IS(0, MT_DM_CLUSTER_DESCRIPTOR, 3, 1, 2);    /* root lists endpoints 1 and 2 */

    /* Thermostat globals: HEAT only, revision 6, one accepted command, nothing generated, no events. */
    CHECK(rd_int(TS, MT_DM_ATTR_FEATURE_MAP) == 1);
    CHECK(rd_int(TS, MT_DM_ATTR_CLUSTER_REV) == 6);
    LIST_IS(EP, TS, MT_DM_ATTR_ATTR_LIST, 0x0000, 0x0003, 0x0004, 0x0012, 0x0015, 0x0016, 0x001B, 0x001C, 0x0029,
            0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD);
    LIST_IS(EP, TS, MT_DM_ATTR_ACCEPTED_CMDS, 0x00);
    LIST_EMPTY(EP, TS, MT_DM_ATTR_GENERATED_CMDS);
    CHECK(!find_attr(EP, TS, MT_DM_ATTR_EVENT_LIST, &a));

    /* Identify globals: revision 4, no features, command Identify only. */
    CHECK(rd_int(ID, MT_DM_ATTR_FEATURE_MAP) == 0);
    CHECK(rd_int(ID, MT_DM_ATTR_CLUSTER_REV) == 4);
    LIST_IS(EP, ID, MT_DM_ATTR_ATTR_LIST, 0x0000, 0x0001, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD);
    LIST_IS(EP, ID, MT_DM_ATTR_ACCEPTED_CMDS, 0x00);
    LIST_EMPTY(EP, ID, MT_DM_ATTR_GENERATED_CMDS);

    /* Quality and access: F on the absolute limits only, write privileges as in the 1.3 XML. */
    CHECK(find_attr(EP, TS, MT_TSTAT_ABS_MIN_HEAT, &a) && (a.flags & MT_IM_ATTR_FIXED) && !(a.flags & MT_IM_ATTR_WRITABLE));
    CHECK(find_attr(EP, TS, MT_TSTAT_ABS_MAX_HEAT, &a) && (a.flags & MT_IM_ATTR_FIXED));
    CHECK(find_attr(EP, TS, MT_TSTAT_LOCAL_TEMPERATURE, &a) && !(a.flags & (MT_IM_ATTR_FIXED | MT_IM_ATTR_WRITABLE)));
    CHECK(find_attr(EP, TS, MT_TSTAT_OCC_HEAT_SETPOINT, &a) && (a.flags & MT_IM_ATTR_WRITABLE) &&
          a.read_priv == MT_IM_PRIV_VIEW && a.write_priv == MT_IM_PRIV_OPERATE);
    CHECK(find_attr(EP, TS, MT_TSTAT_SYSTEM_MODE, &a) && (a.flags & MT_IM_ATTR_WRITABLE) && a.write_priv == MT_IM_PRIV_MANAGE);
    CHECK(find_attr(EP, TS, MT_TSTAT_RUNNING_STATE, &a) && !(a.flags & MT_IM_ATTR_WRITABLE));
    CHECK(find_attr(EP, ID, MT_IDENTIFY_TIME, &a) && (a.flags & MT_IM_ATTR_WRITABLE) && a.write_priv == MT_IM_PRIV_OPERATE);
    CHECK(find_attr(EP, ID, MT_IDENTIFY_TYPE, &a) && !(a.flags & (MT_IM_ATTR_WRITABLE | MT_IM_ATTR_FIXED)));

    /* Command metadata: SetpointRaiseLower needs Operate, Identify needs Manage, neither is timed. */
    uint8_t priv = 0;
    bool timed = true;
    mt_im_cmd c = { EP, TS, 0 };
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_OK && priv == MT_IM_PRIV_OPERATE && !timed);
    c.cluster = ID;
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_OK && priv == MT_IM_PRIV_MANAGE && !timed);
    c.command = 0x40;   /* TriggerEffect: optional, not implemented */
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_ERR_NOT_FOUND);

    /* Bad configuration is refused. */
    mt_thermostat bad;
    mt_thermostat_cfg c0 = { .model = NULL };
    CHECK(mt_thermostat_init(&bad, &c0) == MT_ERR_INVALID);
    c0.model = &g_model;
    c0.identify_type = 6;
    CHECK(mt_thermostat_init(&bad, &c0) == MT_ERR_INVALID);
}

static void test_reads(void)
{
    setup(true, 2);
    CHECK(rd_int(TS, MT_TSTAT_LOCAL_TEMPERATURE) == 2150);
    CHECK(rd_int(TS, MT_TSTAT_ABS_MIN_HEAT) == 500 && rd_int(TS, MT_TSTAT_ABS_MAX_HEAT) == 4000);
    CHECK(rd_int(TS, MT_TSTAT_MIN_HEAT) == 500 && rd_int(TS, MT_TSTAT_MAX_HEAT) == 4000);
    CHECK(rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 2000);
    CHECK(rd_int(TS, MT_TSTAT_CONTROL_SEQUENCE) == 2);
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == 4);
    CHECK(rd_int(TS, MT_TSTAT_RUNNING_STATE) == 0);
    CHECK(rd_int(ID, MT_IDENTIFY_TIME) == 0 && rd_int(ID, MT_IDENTIFY_TYPE) == 2);

    /* SystemMode: Off only when the switch is off; hold, smart and holiday all read Heat. */
    feed(THERMO_DP_MODE, 1);
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == 4);
    feed(THERMO_DP_MODE, 0);
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == 4);
    feed(THERMO_DP_SWITCH, 0);
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == 0);
    /* ThermostatRunningState bit 0 follows DP3 (heating) and is 0 while off. */
    feed(THERMO_DP_STATE, 1);
    CHECK(rd_int(TS, MT_TSTAT_RUNNING_STATE) == 0);
    feed(THERMO_DP_SWITCH, 1);
    CHECK(rd_int(TS, MT_TSTAT_RUNNING_STATE) == MT_TSTAT_RUNNING_HEAT);
    feed(THERMO_DP_STATE, 0);
    CHECK(rd_int(TS, MT_TSTAT_RUNNING_STATE) == 0);

    /* Negative temperatures are signed. */
    feed(THERMO_DP_CURRENT, -35);
    CHECK(rd_int(TS, MT_TSTAT_LOCAL_TEMPERATURE) == -350);
    /* Out-of-range MCU values saturate (no int32 overflow in the * 10). */
    feed(THERMO_DP_CURRENT, INT32_MAX);
    CHECK(rd_int(TS, MT_TSTAT_LOCAL_TEMPERATURE) == INT16_MAX);
    feed(THERMO_DP_CURRENT, INT32_MIN);
    CHECK(rd_int(TS, MT_TSTAT_LOCAL_TEMPERATURE) == -27315);
    feed(THERMO_DP_CURRENT, 3277);
    CHECK(rd_int(TS, MT_TSTAT_LOCAL_TEMPERATURE) == INT16_MAX);
    feed(THERMO_DP_CURRENT, -35);

    /* LocalTemperature is null until DP24 is reported, and again while a sensor fault is set. */
    setup(false, 0);
    CHECK(rd_null(TS, MT_TSTAT_LOCAL_TEMPERATURE));
    feed(THERMO_DP_CURRENT, 190);
    CHECK(rd_int(TS, MT_TSTAT_LOCAL_TEMPERATURE) == 1900);
    feed(THERMO_DP_FAULT, 2);
    CHECK(rd_null(TS, MT_TSTAT_LOCAL_TEMPERATURE));
    feed(THERMO_DP_FAULT, 0);
    CHECK(rd_int(TS, MT_TSTAT_LOCAL_TEMPERATURE) == 1900);
    /* An unreported model still reads in range: setpoint clamps to the minimum. */
    setup(false, 0);
    CHECK(rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 500);
}

static void test_setpoint_write(void)
{
    setup(true, 0);
    mark_t m = mark();
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_INT, 2100) == MT_IM_SUCCESS);
    CHECK(rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 2100);
    CHECK(g_on_write == 1);
    CHECK(bumped(m, 1) && last_dirty_id() == MT_TSTAT_OCC_HEAT_SETPOINT);
    mt_thermostat_sync(&g_t, &g_dm);          /* the write already updated the snapshot: no second mark */
    CHECK(bumped(m, 1));
    thermo_write w[THERMO_MAX_WRITES];
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 1 && w[0].dp == THERMO_DP_SETPOINT &&
          w[0].value == 210);
    feed(THERMO_DP_SETPOINT, 210);            /* the MCU echo matches: nothing new to tell Matter */
    CHECK(bumped(m, 1));

    /* thermo rounds to 0.5 C (half up): 21.25 -> 21.5, 20.24 -> 20.0. */
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_INT, 2125) == MT_IM_SUCCESS);
    CHECK(rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 2150);
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_INT, 2024) == MT_IM_SUCCESS);
    CHECK(rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 2000);
    /* The limits themselves are valid (unsigned encodings too). */
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_INT, 500) == MT_IM_SUCCESS && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 500);
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_UINT, 4000) == MT_IM_SUCCESS && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 4000);

    /* Rejections change nothing: no model change, no callback, no data version bump. */
    g_on_write = 0;
    m = mark();
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_INT, 499) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_INT, 4001) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_INT, -27315) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_UINT, 70000) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_NULL, 0) == MT_IM_CONSTRAINT_ERROR);   /* not nullable */
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_STR, 0) == MT_IM_INVALID_DATA_TYPE);
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_BOOL, 1) == MT_IM_INVALID_DATA_TYPE);
    CHECK(g_on_write == 0 && bumped(m, 0) && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 4000);
}

static void test_mode_write(void)
{
    setup(true, 0);
    thermo_write w[THERMO_MAX_WRITES];
    mark_t m = mark();

    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_UINT, MT_TSTAT_MODE_OFF) == MT_IM_SUCCESS);
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == 0 && g_on_write == 1);
    CHECK(bumped(m, 1) && last_dirty_id() == MT_TSTAT_SYSTEM_MODE);
    mt_thermostat_sync(&g_t, &g_dm);
    CHECK(bumped(m, 1));
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 1 && w[0].dp == THERMO_DP_SWITCH && w[0].value == 0);
    feed(THERMO_DP_SWITCH, 0);
    CHECK(bumped(m, 1));

    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_UINT, MT_TSTAT_MODE_HEAT) == MT_IM_SUCCESS);
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == 4);
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 1 && w[0].dp == THERMO_DP_SWITCH && w[0].value == 1);
    feed(THERMO_DP_SWITCH, 1);

    /* Heat on a unit running its weekly schedule takes it to hold (thermo: HEAT writes DP2 = hold), even
     * though Matter already read Heat. */
    feed(THERMO_DP_MODE, 1);
    mark_t m2 = mark();
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == 4);
    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_UINT, MT_TSTAT_MODE_HEAT) == MT_IM_SUCCESS);
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 1 && w[0].dp == THERMO_DP_MODE && w[0].value == 2);
    (void)m2;

    /* Only Off and Heat exist (no AUTO feature, heating-only): everything else is CONSTRAINT_ERROR. */
    int on = g_on_write;
    m = mark();
    static const int bad[] = { 1, 2, 3, 5, 6, 7, 8, 9, 10, 255 };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_UINT, bad[i]) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_UINT, 260) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_INT, -1) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_NULL, 0) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_STR, 0) == MT_IM_INVALID_DATA_TYPE);
    CHECK(g_on_write == on && bumped(m, 0) && !thermo_has_writes(&g_model));

    /* ControlSequenceOfOperation: HeatingOnly is the only value, and writing it changes nothing. */
    CHECK(wr(TS, MT_TSTAT_CONTROL_SEQUENCE, V_UINT, 2) == MT_IM_SUCCESS);
    CHECK(wr(TS, MT_TSTAT_CONTROL_SEQUENCE, V_UINT, 4) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(TS, MT_TSTAT_CONTROL_SEQUENCE, V_UINT, 0) == MT_IM_CONSTRAINT_ERROR);
    CHECK(rd_int(TS, MT_TSTAT_CONTROL_SEQUENCE) == 2 && g_on_write == on);

    /* Read-only attributes and list appends. */
    CHECK(wr(TS, MT_TSTAT_LOCAL_TEMPERATURE, V_INT, 2000) == MT_IM_UNSUPPORTED_WRITE);
    CHECK(wr(TS, MT_TSTAT_MIN_HEAT, V_INT, 600) == MT_IM_UNSUPPORTED_WRITE);
    CHECK(wr(TS, MT_TSTAT_RUNNING_STATE, V_UINT, 1) == MT_IM_UNSUPPORTED_WRITE);
    mt_im_attr a;
    mt_im_wctx wc = { &k_subj, false, false };
    mt_tlv_rd r = mk_val(V_UINT, 4);
    CHECK(find_attr(EP, TS, MT_TSTAT_SYSTEM_MODE, &a));
    CHECK(mt_dm_im.write(&g_dm, &wc, &a, MT_IM_WR_LIST_APPEND, &r) == MT_IM_INVALID_ACTION);
}

/* ---------------- endpoint 2: Schedule (On/Off) ---------------- */

#define EP2 MT_SCHEDULE_ENDPOINT
#define OO MT_ONOFF_CLUSTER_ID

static bool rd_onoff(void)
{
    uint8_t b[16];
    mt_tlv_rd r;
    bool v = false;
    CHECK(read_item(EP2, OO, MT_ONOFF_ON_OFF, 0, b, sizeof b, &r) == MT_OK && r.type == MT_TLV_BOOL);
    CHECK(mt_tlv_get_bool(&r, &v) == MT_OK);
    return v;
}

static mt_im_status inv2(uint32_t cmd)   /* fields: an empty struct, as controllers send it */
{
    mt_tlv_wr w, resp;
    mt_tlv_rd r;
    uint8_t rb[16];
    uint32_t resp_cmd = MT_IM_WILD_ID;
    mt_im_cmd c = { EP2, OO, cmd };
    mt_tlv_wr_init(&w, mt_buf_of(g_fbuf, sizeof g_fbuf));
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_end(&w);
    mt_tlv_rd_init(&r, mt_tlv_wr_span(&w));
    mt_tlv_next(&r);
    mt_tlv_wr_init(&resp, mt_buf_of(rb, sizeof rb));
    mt_im_status st = mt_dm_im.invoke(&g_dm, &k_subj, &c, &r, &resp, &resp_cmd);
    CHECK(resp_cmd == MT_IM_WILD_ID && resp.len == 0);
    return st;
}

static uint32_t dataver2(void)
{
    uint32_t v = 0;
    CHECK(mt_dm_dataver(&g_dm, EP2, OO, &v));
    return v;
}

static void test_schedule(void)
{
    setup(true, 0);   /* switch on, hold */
    thermo_write w[THERMO_MAX_WRITES];
    uint8_t priv = 0;
    bool timed = true;

    /* Structure: device type On/Off Plug-in Unit rev 3, On/Off rev 6 without features, Off/On/Toggle. */
    CHECK(g_t.eps[1].id == 2 && g_t.eps[1].n_clusters == 2 && g_t.eps[1].n_types == 1);
    CHECK(g_t.sched_types[0].type == 0x010A && g_t.sched_types[0].revision == 3);
    LIST_IS(EP2, MT_DM_CLUSTER_DESCRIPTOR, 1, 0x06, 0x1D);
    LIST_EMPTY(EP2, MT_DM_CLUSTER_DESCRIPTOR, 3);
    LIST_IS(EP2, OO, MT_DM_ATTR_ATTR_LIST, 0x0000, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD);
    LIST_IS(EP2, OO, MT_DM_ATTR_ACCEPTED_CMDS, 0x00, 0x01, 0x02);
    mt_im_cmd c = { EP2, OO, MT_ONOFF_CMD_TOGGLE };
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_OK && priv == MT_IM_PRIV_OPERATE && !timed);

    /* Hold reads Off; Off then does nothing. */
    CHECK(!rd_onoff());
    CHECK(inv2(MT_ONOFF_CMD_OFF) == MT_IM_SUCCESS && !thermo_has_writes(&g_model) && g_on_write == 0);

    /* On: DP2 = smart, reads On at once (pending), endpoint 2 reported, Matter SystemMode stays Heat. */
    uint32_t v2 = dataver2();
    CHECK(inv2(MT_ONOFF_CMD_ON) == MT_IM_SUCCESS && g_on_write == 1 && rd_onoff());
    CHECK(dataver2() == v2 + 1 && rd_int(TS, MT_TSTAT_SYSTEM_MODE) == MT_TSTAT_MODE_HEAT);
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 1 && w[0].dp == THERMO_DP_MODE && w[0].value == 1);
    feed(THERMO_DP_MODE, 1);
    CHECK(rd_onoff() && dataver2() == v2 + 1);   /* the echo changes nothing */

    /* Toggle (on -> off): DP2 = hold, the switch and setpoint untouched. */
    CHECK(inv2(MT_ONOFF_CMD_TOGGLE) == MT_IM_SUCCESS && !rd_onoff());
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 1 && w[0].dp == THERMO_DP_MODE && w[0].value == 2);
    feed(THERMO_DP_MODE, 2);

    /* Holiday counts as the program; the MCU changing mode by itself is reported. */
    v2 = dataver2();
    feed(THERMO_DP_MODE, 0);
    CHECK(rd_onoff() && dataver2() == v2 + 1);
    CHECK(inv2(MT_ONOFF_CMD_ON) == MT_IM_SUCCESS && !thermo_has_writes(&g_model));   /* holiday kept */
    feed(THERMO_DP_MODE, 2);

    /* Thermostat off: the program reads Off; Off leaves it off, On turns it on in smart. */
    feed(THERMO_DP_SWITCH, 0);
    CHECK(!rd_onoff());
    CHECK(inv2(MT_ONOFF_CMD_OFF) == MT_IM_SUCCESS && !thermo_has_writes(&g_model));
    CHECK(inv2(MT_ONOFF_CMD_ON) == MT_IM_SUCCESS && rd_onoff());
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == MT_TSTAT_MODE_HEAT);
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 2);

    /* OnOff isn't writable; other commands are unsupported. */
    mt_im_attr a;
    mt_im_wctx wc = { &k_subj, false, false };
    mt_tlv_rd r = mk_val(V_BOOL, 1);
    CHECK(find_attr(EP2, OO, MT_ONOFF_ON_OFF, &a) && !(a.flags & MT_IM_ATTR_WRITABLE));
    CHECK(mt_dm_im.write(&g_dm, &wc, &a, MT_IM_WR_VALUE, &r) != MT_IM_SUCCESS);
    c.command = 0x40;
    CHECK(mt_dm_im.cmd_info(&g_dm, &c, &priv, &timed) == MT_ERR_NOT_FOUND);

    /* A model without the weekly program has no endpoint 2. */
    thermo m2;
    mt_thermostat t2;
    thermo_cfg nc = k_cfg;
    nc.mode_smart = THERMO_RAW_UNKNOWN;
    thermo_init(&m2, &nc);
    mt_thermostat_cfg c2 = { .model = &m2 };
    CHECK(mt_thermostat_init(&t2, &c2) == MT_OK && mt_thermostat_endpoint_count(&t2) == 1);
}

/* cfg.auto_mode: SystemMode Auto is the weekly program, no endpoint 2. */
static void test_auto_mode(void)
{
    thermo_write w[THERMO_MAX_WRITES];
    g_auto_mode = true;
    setup(true, 0);   /* on, hold */
    CHECK(mt_dm_check(&g_node) == MT_OK);
    LIST_IS(0, MT_DM_CLUSTER_DESCRIPTOR, 3, 1);
    CHECK(rd_int(TS, MT_DM_ATTR_FEATURE_MAP) == 0x21);
    LIST_IS(EP, TS, MT_DM_ATTR_ATTR_LIST, 0x0000, 0x0003, 0x0004, 0x0011, 0x0012, 0x0015, 0x0016, 0x0019, 0x001B,
            0x001C, 0x0029, 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD);
    CHECK(rd_int(TS, MT_TSTAT_MIN_DEADBAND) == 25);
    CHECK(rd_int(TS, MT_TSTAT_OCC_COOL_SETPOINT) == 4250);   /* heating max + deadband: never cools */
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == MT_TSTAT_MODE_HEAT);

    /* Auto -> DP2 smart; reads Auto at once; the MCU's echo changes nothing. */
    mark_t m = mark();
    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_UINT, MT_TSTAT_MODE_AUTO) == MT_IM_SUCCESS);
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == MT_TSTAT_MODE_AUTO && bumped(m, 1));
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 1 && w[0].dp == THERMO_DP_MODE && w[0].value == 1);
    feed(THERMO_DP_MODE, 1);
    CHECK(bumped(m, 1));
    /* Heat -> hold. */
    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_UINT, MT_TSTAT_MODE_HEAT) == MT_IM_SUCCESS);
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 1 && w[0].dp == THERMO_DP_MODE && w[0].value == 2);
    feed(THERMO_DP_MODE, 2);
    /* Holiday reads Auto; the unit's own keys are reported. */
    m = mark();
    feed(THERMO_DP_MODE, 0);
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == MT_TSTAT_MODE_AUTO && bumped(m, 1));
    /* From Off, Auto turns the unit on (holiday is kept as it is). The earlier Heat write's hold on DP1 ends first. */
    g_now += THERMO_PENDING_MS;
    mt_thermostat_tick(&g_t, &g_dm);
    feed(THERMO_DP_SWITCH, 0);
    CHECK(rd_int(TS, MT_TSTAT_SYSTEM_MODE) == MT_TSTAT_MODE_OFF);
    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_UINT, MT_TSTAT_MODE_AUTO) == MT_IM_SUCCESS);
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 1 && w[0].dp == THERMO_DP_SWITCH && w[0].value == 1);
    /* Cool and the rest stay invalid. */
    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_UINT, 3) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(TS, MT_TSTAT_SYSTEM_MODE, V_UINT, 7) == MT_IM_CONSTRAINT_ERROR);

    /* auto_mode needs a model with the weekly program. */
    thermo m2;
    mt_thermostat t2;
    thermo_cfg nc = k_cfg;
    nc.mode_smart = THERMO_RAW_UNKNOWN;
    thermo_init(&m2, &nc);
    mt_thermostat_cfg c2 = { .model = &m2, .auto_mode = true };
    CHECK(mt_thermostat_init(&t2, &c2) == MT_ERR_INVALID);
    g_auto_mode = false;
}

static void test_raise_lower(void)
{
    setup(true, 0);
    thermo_write w[THERMO_MAX_WRITES];
    mark_t m = mark();

    /* Heat +1.0 C (Amount is in 0.1 C). */
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, 10, V_INT) == MT_IM_SUCCESS);
    CHECK(rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 2100 && g_on_write == 1);
    CHECK(bumped(m, 1) && last_dirty_id() == MT_TSTAT_OCC_HEAT_SETPOINT);   /* the handler marks, once */
    mt_thermostat_sync(&g_t, &g_dm);
    CHECK(bumped(m, 1));
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 1 && w[0].dp == THERMO_DP_SETPOINT && w[0].value == 210);
    feed(THERMO_DP_SETPOINT, 210);

    /* Both acts as Heat on a heating-only thermostat; negative amounts lower. */
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_BOTH, -30, V_INT) == MT_IM_SUCCESS);
    CHECK(rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 1800);
    feed(THERMO_DP_SETPOINT, 180);

    /* A raise/lower below the 0.5 C step would round back to the current value: it moves one step instead. */
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, 1, V_INT) == MT_IM_SUCCESS && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 1850);
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, 1, V_INT) == MT_IM_SUCCESS && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 1900);   /* pending adds up */
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, -2, V_INT) == MT_IM_SUCCESS && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 1850);
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, 3, V_INT) == MT_IM_SUCCESS && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 1900);   /* 18.80 -> 19.0 */

    /* Amount 0 is a successful no-op. */
    m = mark();
    int on = g_on_write;
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, 0, V_INT) == MT_IM_SUCCESS);
    CHECK(g_on_write == on && bumped(m, 0) && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 1900);

    /* Clamped to the limits, and a no-op at the limit. */
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, 127, V_INT) == MT_IM_SUCCESS && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 3150);
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, 127, V_INT) == MT_IM_SUCCESS && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 4000);
    m = mark();
    on = g_on_write;
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, 5, V_INT) == MT_IM_SUCCESS);
    CHECK(rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 4000 && g_on_write == on && bumped(m, 0));
    for (int i = 0; i < 4; i++) CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, -128, V_INT) == MT_IM_SUCCESS);
    CHECK(rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 500);
    m = mark();
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, -1, V_INT) == MT_IM_SUCCESS && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 500);
    CHECK(bumped(m, 0));

    /* Invalid requests change nothing. */
    on = g_on_write;
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_COOL, 10, V_INT) == MT_IM_INVALID_COMMAND);
    CHECK(inv(TS, 0, true, 3, 10, V_INT) == MT_IM_CONSTRAINT_ERROR);
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, 128, V_INT) == MT_IM_CONSTRAINT_ERROR);
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, -129, V_INT) == MT_IM_CONSTRAINT_ERROR);
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, -1000, V_INT) == MT_IM_INVALID_COMMAND);   /* Amount missing */
    CHECK(inv(TS, 0, true, -1000, 10, V_INT) == MT_IM_INVALID_COMMAND);                    /* Mode missing */
    CHECK(inv(TS, 0, true, MT_TSTAT_RAISE_HEAT, 10, V_BOOL) == MT_IM_INVALID_COMMAND);     /* wrong type */
    CHECK(inv(TS, 0, false, 0, 0, V_INT) == MT_IM_INVALID_COMMAND);                        /* no fields */
    CHECK(inv(TS, 7, true, 0, 10, V_INT) == MT_IM_UNSUPPORTED_COMMAND);
    CHECK(g_on_write == on && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 500);
}

static void test_sync(void)
{
    setup(true, 0);
    mark_t m = mark();

    mt_thermostat_sync(&g_t, &g_dm);          /* nothing changed */
    CHECK(bumped(m, 0));

    feed(THERMO_DP_CURRENT, 220);
    CHECK(bumped(m, 1) && last_dirty_id() == MT_TSTAT_LOCAL_TEMPERATURE);
    feed(THERMO_DP_CURRENT, 220);             /* same report: no mark */
    CHECK(bumped(m, 1));

    feed(THERMO_DP_SETPOINT, 250);            /* changed at the unit's own keys */
    CHECK(bumped(m, 2) && last_dirty_id() == MT_TSTAT_OCC_HEAT_SETPOINT);
    CHECK(rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 2500);

    feed(THERMO_DP_MODE, 1);                  /* hold -> schedule: still Heat for Matter */
    feed(108, 1);                             /* child lock: not a model DP */
    CHECK(bumped(m, 2));

    feed(THERMO_DP_STATE, 1);                 /* relay on */
    CHECK(bumped(m, 3) && last_dirty_id() == MT_TSTAT_RUNNING_STATE);
    feed(THERMO_DP_SWITCH, 0);                /* off: mode and running state both change */
    CHECK(bumped(m, 5));
    feed(THERMO_DP_SWITCH, 1);
    CHECK(bumped(m, 7));

    feed(THERMO_DP_FAULT, 2);                 /* null <-> value is a change */
    CHECK(bumped(m, 8) && last_dirty_id() == MT_TSTAT_LOCAL_TEMPERATURE);
    feed(THERMO_DP_FAULT, 1);
    CHECK(bumped(m, 8));
    feed(THERMO_DP_FAULT, 0);
    CHECK(bumped(m, 9));

    /* Other clusters' versions are untouched. */
    uint32_t v = dataver(ID);
    feed(THERMO_DP_CURRENT, 230);
    CHECK(dataver(ID) == v);

    /* Before the first DP24 report the node is null; the report marks it once. */
    setup(false, 0);
    m = mark();
    feed(THERMO_DP_SWITCH, 1);
    feed(THERMO_DP_MODE, 2);
    CHECK(bumped(m, 1));                      /* only SystemMode (Off -> Heat); setpoint stays at its clamp */
    feed(THERMO_DP_CURRENT, 190);
    CHECK(bumped(m, 2) && last_dirty_id() == MT_TSTAT_LOCAL_TEMPERATURE);
}

static void test_hold_expiry(void)
{
    setup(true, 0);
    thermo_write w[THERMO_MAX_WRITES];
    mark_t m = mark();
    CHECK(wr(TS, MT_TSTAT_OCC_HEAT_SETPOINT, V_INT, 2100) == MT_IM_SUCCESS);
    CHECK(thermo_take_writes(&g_model, w, THERMO_MAX_WRITES, g_now) == 1);
    CHECK(bumped(m, 1));
    CHECK(mt_thermostat_tick(&g_t, &g_dm) == 500u);   /* a pending value keeps the tick alive */

    feed(THERMO_DP_SETPOINT, 200);            /* stale echo: held back, Matter keeps seeing 21.0 */
    CHECK(bumped(m, 1) && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 2100);
    g_now += 2999;
    mt_thermostat_tick(&g_t, &g_dm);
    CHECK(bumped(m, 1) && rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 2100);
    g_now += 1;                               /* THERMO_PENDING_MS: the unit never applied it, snap back */
    uint32_t next = mt_thermostat_tick(&g_t, &g_dm);
    CHECK(rd_int(TS, MT_TSTAT_OCC_HEAT_SETPOINT) == 2000);
    CHECK(bumped(m, 2) && last_dirty_id() == MT_TSTAT_OCC_HEAT_SETPOINT);
    CHECK(next == UINT32_MAX);                /* nothing pending, nothing identifying */
}

static void test_identify(void)
{
    setup(true, 2);
    mark_t tm = mark();
    uint32_t v0 = dataver(ID);
    uint32_t gen = g_im.gen;

    CHECK(mt_thermostat_tick(&g_t, &g_dm) == UINT32_MAX);

    /* Write IdentifyTime: starts the callback, the DM bumps and marks it. */
    CHECK(wr(ID, MT_IDENTIFY_TIME, V_UINT, 3) == MT_IM_SUCCESS);
    CHECK(rd_int(ID, MT_IDENTIFY_TIME) == 3 && g_ident_calls == 1 && g_ident_active);
    CHECK(dataver(ID) == v0 + 1 && g_im.gen == gen + 1 && last_dirty_id() == MT_IDENTIFY_TIME);
    CHECK(mt_thermostat_tick(&g_t, &g_dm) == 1000u);

    /* Counts down one per second; each step is a change; the stop calls back once. */
    g_now += 999;
    CHECK(mt_thermostat_tick(&g_t, &g_dm) == 1u && rd_int(ID, MT_IDENTIFY_TIME) == 3);
    g_now += 1;
    CHECK(mt_thermostat_tick(&g_t, &g_dm) == 1000u && rd_int(ID, MT_IDENTIFY_TIME) == 2);
    CHECK(dataver(ID) == v0 + 2);
    g_now += 1500;
    CHECK(mt_thermostat_tick(&g_t, &g_dm) == 500u && rd_int(ID, MT_IDENTIFY_TIME) == 1);
    g_now += 500;
    CHECK(mt_thermostat_tick(&g_t, &g_dm) == UINT32_MAX && rd_int(ID, MT_IDENTIFY_TIME) == 0);
    CHECK(dataver(ID) == v0 + 4 && g_ident_calls == 2 && !g_ident_active);
    CHECK(dataver(TS) == tm.ver);             /* the Thermostat cluster was not touched */

    /* A late tick (task was busy) catches up in one go. */
    CHECK(wr(ID, MT_IDENTIFY_TIME, V_UINT, 2) == MT_IM_SUCCESS);
    g_now += 5000;
    CHECK(mt_thermostat_tick(&g_t, &g_dm) == UINT32_MAX && rd_int(ID, MT_IDENTIFY_TIME) == 0);
    CHECK(g_ident_calls == 4 && !g_ident_active);

    /* The Identify command: sets the time, marks once, restarting a running identify does not call back. */
    uint32_t v = dataver(ID);
    CHECK(inv(ID, 0, true, 10, -1000, V_INT) == MT_IM_SUCCESS);
    CHECK(rd_int(ID, MT_IDENTIFY_TIME) == 10 && g_ident_calls == 5 && g_ident_active);
    CHECK(dataver(ID) == v + 1 && last_dirty_id() == MT_IDENTIFY_TIME);
    CHECK(inv(ID, 0, true, 20, -1000, V_INT) == MT_IM_SUCCESS);
    CHECK(rd_int(ID, MT_IDENTIFY_TIME) == 20 && g_ident_calls == 5 && dataver(ID) == v + 2);
    CHECK(inv(ID, 0, true, 0, -1000, V_INT) == MT_IM_SUCCESS);        /* 0 stops */
    CHECK(rd_int(ID, MT_IDENTIFY_TIME) == 0 && g_ident_calls == 6 && !g_ident_active);
    CHECK(mt_thermostat_tick(&g_t, &g_dm) == UINT32_MAX);

    /* Rejections. */
    v = dataver(ID);
    CHECK(inv(ID, 0, true, -1000, -1000, V_INT) == MT_IM_INVALID_COMMAND);
    CHECK(inv(ID, 0, false, 0, 0, V_INT) == MT_IM_INVALID_COMMAND);
    CHECK(inv(ID, 0, true, 65536, -1000, V_INT) == MT_IM_CONSTRAINT_ERROR);
    CHECK(inv(ID, 0, true, -1, -1000, V_INT) == MT_IM_CONSTRAINT_ERROR);
    CHECK(inv(ID, 0x40, true, 0, 0, V_INT) == MT_IM_UNSUPPORTED_COMMAND);   /* TriggerEffect */
    CHECK(wr(ID, MT_IDENTIFY_TIME, V_UINT, 65536) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(ID, MT_IDENTIFY_TIME, V_INT, -1) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(ID, MT_IDENTIFY_TIME, V_NULL, 0) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr(ID, MT_IDENTIFY_TIME, V_BOOL, 1) == MT_IM_INVALID_DATA_TYPE);
    CHECK(wr(ID, MT_IDENTIFY_TYPE, V_UINT, 1) == MT_IM_UNSUPPORTED_WRITE);
    CHECK(dataver(ID) == v && rd_int(ID, MT_IDENTIFY_TIME) == 0 && g_ident_calls == 6);
    CHECK(wr(ID, MT_IDENTIFY_TIME, V_UINT, 65535) == MT_IM_SUCCESS && rd_int(ID, MT_IDENTIFY_TIME) == 65535);

    /* Identify works without callbacks. */
    mt_thermostat bare;
    mt_thermostat_cfg c = { .model = &g_model };
    CHECK(mt_thermostat_init(&bare, &c) == MT_OK);
}

int main(void)
{
    test_structure();
    test_reads();
    test_setpoint_write();
    test_mode_write();
    test_raise_lower();
    test_sync();
    test_hold_expiry();
    test_identify();
    test_schedule();
    test_auto_mode();
    printf("matter-thermostat: %d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
