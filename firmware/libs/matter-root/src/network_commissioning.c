/* Network Commissioning cluster (0x31, spec 1.3 section 11.9), Wi-Fi feature; see mt_netcomm.h.
 * Command rules as in connectedhomeip v1.3 network-commissioning.cpp. */
#include "mt_netcomm.h"
#include "root_priv.h"

enum { A_MAX = 0, A_NETWORKS = 1, A_SCAN_MAX = 2, A_CONN_MAX = 3, A_ENABLED = 4, A_LAST_STATUS = 5, A_LAST_ID = 6,
       A_LAST_ERR = 7, A_BANDS = 8 };
enum { C_SCAN = 0, C_SCAN_RESP = 1, C_ADD_WIFI = 2, C_REMOVE = 4, C_CONFIG_RESP = 5, C_CONNECT = 6,
       C_CONNECT_RESP = 7, C_REORDER = 8 };
enum { ST_NONE = 0, ST_SET, ST_REMOVE };   /* staged change */
enum { OP_NONE = 0, OP_SCAN, OP_CONNECT }; /* operation in flight */

#define FEATURE_WIFI 1u
#define MAX_NETWORKS 1
#define DEFAULT_SCAN_S 10
#define DEFAULT_CONNECT_S 30

#define V MT_IM_PRIV_VIEW
#define ADM MT_IM_PRIV_ADMINISTER
#define FX MT_IM_ATTR_FIXED

static const mt_dm_attr_def attrs[] = {
    { A_MAX, FX, ADM, 0 },
    { A_NETWORKS, MT_IM_ATTR_LIST, ADM, 0 },
    { A_SCAN_MAX, FX, V, 0 },
    { A_CONN_MAX, FX, V, 0 },
    { A_ENABLED, MT_IM_ATTR_WRITABLE, V, ADM },
    { A_LAST_STATUS, 0, ADM, 0 },
    { A_LAST_ID, 0, ADM, 0 },
    { A_LAST_ERR, 0, ADM, 0 },
    { A_BANDS, MT_IM_ATTR_LIST | FX, V, 0 },
};
static const mt_dm_cmd_def cmds[] = { { C_SCAN, ADM, false }, { C_ADD_WIFI, ADM, false }, { C_REMOVE, ADM, false },
                                      { C_CONNECT, ADM, false }, { C_REORDER, ADM, false } };
static const uint32_t generated[] = { C_SCAN_RESP, C_CONFIG_RESP, C_CONNECT_RESP };

/* ---- helpers ---- */

static void changed(mt_netcomm *n, uint32_t attr) { root_changed(n->c.root, MT_NETCOMM_CLUSTER_ID, attr); }

/* The network list as a controller sees it: the staged change over the persisted network. */
static bool cur_net(const mt_netcomm *n, uint8_t ssid[MT_NETCTL_SSID_MAX], size_t *len)
{
    if (n->stage.kind == ST_SET) {
        memcpy(ssid, n->stage.ssid, n->stage.ssid_len);
        *len = n->stage.ssid_len;
        return true;
    }
    if (n->stage.kind == ST_REMOVE) return false;
    *len = 0;
    return n->c.net->saved(n->c.ctx, ssid, len) && *len && *len <= MT_NETCTL_SSID_MAX;
}

static bool same_id(const uint8_t *a, size_t al, mt_span b) { return al == b.len && (al == 0 || !memcmp(a, b.p, al)); }

static void last_changed(mt_netcomm *n)
{
    changed(n, A_LAST_STATUS);
    changed(n, A_LAST_ID);
    changed(n, A_LAST_ERR);
}

static void set_last(mt_netcomm *n, uint8_t status, const uint8_t *id, size_t id_len, const int32_t *err)
{
    n->have_status = true;
    n->last_status = status;
    n->have_error = err != NULL;
    n->last_error = err ? *err : 0;
    if (id) {
        n->last_id_len = (uint8_t)id_len;
        memcpy(n->last_id, id, id_len);
    }
    last_changed(n);
}

static void clear_last(mt_netcomm *n)
{
    n->have_status = n->have_error = false;
    n->last_id_len = 0;
    last_changed(n);
}

/* Answer a deferred ScanNetworks/ConnectNetwork. */
static void complete(mt_netcomm *n, uint32_t resp_cmd, mt_span fields)
{
    uint16_t session = n->op.session, exch = n->op.exch;
    mt_dm *dm = n->c.root->dm;
    n->op.kind = OP_NONE;
    if (dm && dm->im) mt_im_invoke_done(dm->im, session, exch, MT_IM_SUCCESS, resp_cmd, fields);
}

static bool creds_valid(mt_span c)
{
    if (c.len == 0 || c.len == 5 || (c.len >= 8 && c.len <= 63)) return true; /* open, WEP-64, WPA passphrase */
    if (c.len != 64) return false;
    for (size_t i = 0; i < c.len; i++) {
        uint8_t ch = c.p[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return false;
    }
    return true;
}

/* ---- attributes ---- */

static mt_err nc_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                      mt_tlv_tag tag)
{
    mt_netcomm *n = at->cl->ctx;
    uint8_t ssid[MT_NETCTL_SSID_MAX], conn[MT_NETCTL_SSID_MAX];
    size_t len = 0, clen = 0;
    (void)rc;
    switch (attr) {
    case A_MAX: return mt_tlv_put_u(w, tag, MAX_NETWORKS);
    case A_NETWORKS: {
        mt_tlv_mark m;
        mt_err e;
        bool up;
        if (item || !cur_net(n, ssid, &len)) return MT_ERR_NOT_FOUND;
        up = n->c.net->connected(n->c.ctx, conn, &clen) && clen == len && !memcmp(conn, ssid, len);
        m = mt_tlv_wr_mark(w);
        e = mt_tlv_start(w, tag, MT_TLV_STRUCT);
        if (!e) e = mt_tlv_put_bytes(w, CTX(0), mt_span_of(ssid, len));
        if (!e) e = mt_tlv_put_bool(w, CTX(1), up);
        if (!e) e = mt_tlv_end(w);
        if (e) mt_tlv_wr_rollback(w, m);
        return e;
    }
    case A_SCAN_MAX: return mt_tlv_put_u(w, tag, n->c.scan_max_s);
    case A_CONN_MAX: return mt_tlv_put_u(w, tag, n->c.connect_max_s);
    case A_ENABLED: return mt_tlv_put_bool(w, tag, n->enabled);
    case A_LAST_STATUS: return n->have_status ? mt_tlv_put_u(w, tag, n->last_status) : mt_tlv_put_null(w, tag);
    case A_LAST_ID:
        return n->last_id_len ? mt_tlv_put_bytes(w, tag, mt_span_of(n->last_id, n->last_id_len))
                              : mt_tlv_put_null(w, tag);
    case A_LAST_ERR: return n->have_error ? mt_tlv_put_i(w, tag, n->last_error) : mt_tlv_put_null(w, tag);
    case A_BANDS:
        for (unsigned b = 0, seen = 0; b < 8; b++)
            if (n->c.bands & (1u << b) && seen++ == item) return mt_tlv_put_u(w, tag, b);
        return MT_ERR_NOT_FOUND;
    default: return MT_ERR_NOT_FOUND;
    }
}

static mt_im_status nc_write(const mt_dm_at *at, const mt_im_wctx *wc, uint32_t attr, mt_im_wr_op op, mt_tlv_rd *val)
{
    mt_netcomm *n = at->cl->ctx;
    bool v;
    (void)wc;
    if (attr != A_ENABLED) return MT_IM_UNSUPPORTED_WRITE;
    if (op != MT_IM_WR_VALUE) return MT_IM_INVALID_ACTION;
    if (mt_tlv_get_bool(val, &v)) return MT_IM_INVALID_DATA_TYPE;
    if (n->c.net->set_enabled && n->c.net->set_enabled(n->c.ctx, v)) return MT_IM_FAILURE;
    n->enabled = v;
    return MT_IM_SUCCESS;
}

/* ---- commands ---- */

/* NetworkConfigResponse {0: NetworkingStatus, 2: NetworkIndex (on success)} */
static mt_im_status config_resp(mt_tlv_wr *resp, uint32_t *resp_cmd, uint8_t status, uint8_t index)
{
    if (mt_tlv_put_u(resp, CTX(0), status) || (status == MT_NET_OK && mt_tlv_put_u(resp, CTX(2), index)))
        return MT_IM_RESOURCE_EXHAUSTED;
    *resp_cmd = C_CONFIG_RESP;
    return MT_IM_SUCCESS;
}

/* Optional Breadcrumb at `tag`: MT_OK absent or valid, MT_ERR_INVALID on a bad type. */
static mt_err get_crumb(const mt_tlv_rd *f, uint8_t tag, bool *set, uint64_t *crumb)
{
    mt_tlv_rd x;
    mt_err e = mt_im_field(f, tag, &x);
    *set = false;
    if (e == MT_ERR_NOT_FOUND) return MT_OK;
    if (e || mt_tlv_get_u64(&x, crumb)) return MT_ERR_INVALID;
    *set = true;
    return MT_OK;
}

static mt_im_status add_or_update(mt_netcomm *n, const mt_im_subject *s, mt_tlv_rd *f,
                                  mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_tlv_rd x;
    mt_span ssid, cred;
    uint8_t cur[MT_NETCTL_SSID_MAX];
    size_t cl = 0;
    bool crumb_set;
    uint64_t crumb = 0;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_bytes(&x, &ssid) || mt_im_field(f, 1, &x) || mt_tlv_get_bytes(&x, &cred) ||
        get_crumb(f, 2, &crumb_set, &crumb))
        return MT_IM_INVALID_COMMAND;
    if (!root_fs_armed_for(n->c.root, s->fabric)) return MT_IM_FAILSAFE_REQUIRED;
    if (ssid.len == 0 || ssid.len > MT_NETCTL_SSID_MAX) return MT_IM_CONSTRAINT_ERROR;
    if (mt_im_field(f, 3, &x) == MT_OK) return MT_IM_INVALID_COMMAND; /* NetworkIdentity: PDC not supported */
    if (!creds_valid(cred)) return MT_IM_CONSTRAINT_ERROR;
    if (cur_net(n, cur, &cl) && !same_id(cur, cl, ssid) && !n->c.replace_when_full)
        return config_resp(resp, resp_cmd, MT_NET_BOUNDS_EXCEEDED, 0);
    n->stage.kind = ST_SET;
    n->stage.ssid_len = (uint8_t)ssid.len;
    memcpy(n->stage.ssid, ssid.p, ssid.len);
    n->stage.cred_len = (uint8_t)cred.len;
    memcpy(n->stage.cred, cred.p, cred.len);
    n->c.root->fs.flags |= MT_FS_NETWORK;
    changed(n, A_NETWORKS);
    if (crumb_set) root_set_breadcrumb(n->c.root, crumb);
    return config_resp(resp, resp_cmd, MT_NET_OK, 0);
}

static mt_im_status remove_network(mt_netcomm *n, const mt_im_subject *s, mt_tlv_rd *f,
                                   mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_tlv_rd x;
    mt_span id;
    uint8_t cur[MT_NETCTL_SSID_MAX];
    size_t cl = 0;
    bool crumb_set;
    uint64_t crumb = 0;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_bytes(&x, &id) || get_crumb(f, 1, &crumb_set, &crumb))
        return MT_IM_INVALID_COMMAND;
    if (!root_fs_armed_for(n->c.root, s->fabric)) return MT_IM_FAILSAFE_REQUIRED;
    if (!cur_net(n, cur, &cl) || !same_id(cur, cl, id)) return config_resp(resp, resp_cmd, MT_NET_ID_NOT_FOUND, 0);
    {   /* a staged new network on top of nothing persisted just disappears; otherwise the persisted one is removed */
        uint8_t saved[MT_NETCTL_SSID_MAX];
        size_t sl = 0;
        bool have_saved = n->c.net->saved(n->c.ctx, saved, &sl) && sl;
        n->stage.kind = have_saved ? ST_REMOVE : ST_NONE;
    }
    n->c.root->fs.flags |= MT_FS_NETWORK;
    changed(n, A_NETWORKS);
    if (crumb_set) root_set_breadcrumb(n->c.root, crumb);
    clear_last(n); /* no network left: chip clears the connect results */
    return config_resp(resp, resp_cmd, MT_NET_OK, 0);
}

static mt_im_status reorder(mt_netcomm *n, const mt_im_subject *s, mt_tlv_rd *f, mt_tlv_wr *resp,
                            uint32_t *resp_cmd)
{
    mt_tlv_rd x;
    mt_span id;
    uint8_t index, cur[MT_NETCTL_SSID_MAX];
    size_t cl = 0;
    bool crumb_set;
    uint64_t crumb = 0;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_bytes(&x, &id) || mt_im_field(f, 1, &x) || mt_tlv_get_u8(&x, &index) ||
        get_crumb(f, 2, &crumb_set, &crumb))
        return MT_IM_INVALID_COMMAND;
    if (!root_fs_armed_for(n->c.root, s->fabric)) return MT_IM_FAILSAFE_REQUIRED;
    if (!cur_net(n, cur, &cl) || !same_id(cur, cl, id)) return config_resp(resp, resp_cmd, MT_NET_ID_NOT_FOUND, index);
    if (index >= MAX_NETWORKS) return config_resp(resp, resp_cmd, MT_NET_OUT_OF_RANGE, index);
    if (crumb_set) root_set_breadcrumb(n->c.root, crumb); /* a single network: nothing to move */
    return config_resp(resp, resp_cmd, MT_NET_OK, index);
}

/* Defer the invoke: the answer goes out from complete() when the port reports back or the timeout hits. */
static mt_im_status begin_op(mt_netcomm *n, const mt_dm_at *at, const mt_im_subject *s, uint8_t kind,
                             uint32_t timeout_s, bool crumb_set, uint64_t crumb)
{
    n->op.kind = kind;
    n->op.aborted = false;
    n->op.session = s->session;
    n->op.exch = mt_im_invoke_exch(at->dm->im);
    n->op.deadline = n->c.root->c.ops->now_ms(n->c.root->c.ctx) + timeout_s * 1000u;
    n->op.crumb_set = crumb_set;
    n->op.crumb = crumb;
    return MT_IM_DEFER;
}

/* ConnectNetworkResponse {0: NetworkingStatus, 2: ErrorValue (nullable)} */
static mt_err connect_fields(mt_tlv_wr *w, uint8_t status, const int32_t *err)
{
    mt_err e = mt_tlv_put_u(w, CTX(0), status);
    if (!e) e = err ? mt_tlv_put_i(w, CTX(2), *err) : mt_tlv_put_null(w, CTX(2));
    return e;
}

static mt_im_status connect_now(mt_tlv_wr *resp, uint32_t *resp_cmd, uint8_t status, const int32_t *err)
{
    if (connect_fields(resp, status, err)) return MT_IM_RESOURCE_EXHAUSTED;
    *resp_cmd = C_CONNECT_RESP;
    return MT_IM_SUCCESS;
}

static mt_im_status connect_network(mt_netcomm *n, const mt_dm_at *at, const mt_im_subject *s, mt_tlv_rd *f,
                                    mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_tlv_rd x;
    mt_span id;
    uint8_t cur[MT_NETCTL_SSID_MAX], now_on[MT_NETCTL_SSID_MAX];
    size_t cl = 0, nl = 0;
    bool crumb_set, staged;
    uint64_t crumb = 0;
    mt_span cred;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_bytes(&x, &id) || get_crumb(f, 1, &crumb_set, &crumb))
        return MT_IM_INVALID_COMMAND;
    if (id.len > MT_NETCTL_SSID_MAX) return MT_IM_CONSTRAINT_ERROR;
    if (!root_fs_armed_for(n->c.root, s->fabric)) return MT_IM_FAILSAFE_REQUIRED;
    if (!cur_net(n, cur, &cl) || !same_id(cur, cl, id)) {
        set_last(n, MT_NET_ID_NOT_FOUND, id.p, id.len, NULL);
        return connect_now(resp, resp_cmd, MT_NET_ID_NOT_FOUND, NULL);
    }
    staged = n->stage.kind == ST_SET;
    cred = mt_span_of(n->stage.cred, n->stage.cred_len);

    /* Already on it: the answer is immediate and nothing moves. */
    if (n->c.net->connected(n->c.ctx, now_on, &nl) && nl == cl && !memcmp(now_on, cur, cl) &&
        (!staged || !n->c.net->is_current || n->c.net->is_current(n->c.ctx, mt_span_of(cur, cl), cred))) {
        set_last(n, MT_NET_OK, cur, cl, NULL);
        if (crumb_set) root_set_breadcrumb(n->c.root, crumb);
        return connect_now(resp, resp_cmd, MT_NET_OK, NULL);
    }

    if (!at->dm->im) return MT_IM_FAILURE; /* cannot answer later */
    if (n->c.net->connect(n->c.ctx, mt_span_of(cur, cl), staged ? &cred : NULL)) {
        set_last(n, MT_NET_OTHER_CONNECTION_FAILURE, cur, cl, NULL);
        return connect_now(resp, resp_cmd, MT_NET_OTHER_CONNECTION_FAILURE, NULL);
    }
    n->switched = true;
    n->c.root->fs.flags |= MT_FS_NETWORK;
    n->op.id_len = (uint8_t)cl;
    memcpy(n->op.id, cur, cl);
    return begin_op(n, at, s, OP_CONNECT, n->c.connect_max_s, crumb_set, crumb);
}

static mt_im_status scan_networks(mt_netcomm *n, const mt_dm_at *at, const mt_im_subject *s, mt_tlv_rd *f,
                                  mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_tlv_rd x;
    mt_span ssid = mt_span_of(NULL, 0);
    bool crumb_set;
    uint64_t crumb = 0;
    mt_err e = mt_im_field(f, 0, &x);
    if (e == MT_ERR_INVALID || (!e && x.type != MT_TLV_NULL && mt_tlv_get_bytes(&x, &ssid))) return MT_IM_INVALID_COMMAND;
    if (get_crumb(f, 1, &crumb_set, &crumb)) return MT_IM_INVALID_COMMAND;
    if (ssid.len > MT_NETCTL_SSID_MAX) {
        set_last(n, MT_NET_UNKNOWN_ERROR, NULL, 0, NULL);
        return MT_IM_CONSTRAINT_ERROR;
    }
    if (!at->dm->im) return MT_IM_FAILURE;
    if (n->c.net->scan(n->c.ctx, ssid)) {
        set_last(n, MT_NET_OTHER_CONNECTION_FAILURE, NULL, 0, NULL);
        if (mt_tlv_put_u(resp, CTX(0), MT_NET_OTHER_CONNECTION_FAILURE)) return MT_IM_RESOURCE_EXHAUSTED;
        *resp_cmd = C_SCAN_RESP;
        return MT_IM_SUCCESS;
    }
    return begin_op(n, at, s, OP_SCAN, n->c.scan_max_s, crumb_set, crumb);
}

static mt_im_status nc_invoke(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                              mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_netcomm *n = at->cl->ctx;
    if (n->op.kind) return MT_IM_BUSY; /* one async operation at a time */
    switch (cmd) {
    case C_SCAN: return scan_networks(n, at, s, fields, resp, resp_cmd);
    case C_ADD_WIFI: return add_or_update(n, s, fields, resp, resp_cmd);
    case C_REMOVE: return remove_network(n, s, fields, resp, resp_cmd);
    case C_CONNECT: return connect_network(n, at, s, fields, resp, resp_cmd);
    case C_REORDER: return reorder(n, s, fields, resp, resp_cmd);
    default: return MT_IM_UNSUPPORTED_COMMAND;
    }
}

static const mt_dm_ops ops = { nc_read, nc_write, nc_invoke };

/* ---- results from the port ---- */

void mt_netcomm_connect_done(mt_netcomm *n, uint8_t status, const int32_t *err)
{
    uint8_t buf[16];
    mt_tlv_wr w;
    mt_span f;
    if (n->op.kind != OP_CONNECT) return;
    if (n->op.aborted) { /* the fail-safe expired meanwhile: the station went back */
        status = MT_NET_OTHER_CONNECTION_FAILURE;
        err = NULL;
    }
    set_last(n, status, n->op.id, n->op.id_len, status == MT_NET_OK ? NULL : err);
    if (status == MT_NET_OK && n->op.crumb_set) root_set_breadcrumb(n->c.root, n->op.crumb);
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    if (connect_fields(&w, status, err) || mt_tlv_wr_done(&w, &f)) f = mt_span_of(NULL, 0);
    complete(n, C_CONNECT_RESP, f);
}

/* Encode the strongest results into w as ScanNetworksResponse field 2. */
static mt_err put_scan_results(mt_netcomm *n, mt_tlv_wr *w)
{
    uint32_t used = 0;
    mt_err e = mt_tlv_start(w, CTX(2), MT_TLV_ARRAY);
    for (unsigned k = 0; !e && k < MT_NETCOMM_MAX_SCAN_RESULTS; k++) {
        mt_netctl_ap ap;
        int best = -1, best_rssi = 0;
        mt_tlv_mark m;
        for (uint16_t i = 0; i < 32 && n->c.net->scan_result(n->c.ctx, i, &ap); i++)
            if (!(used & (1u << i)) && (best < 0 || ap.rssi > best_rssi)) best = i, best_rssi = ap.rssi;
        if (best < 0 || !n->c.net->scan_result(n->c.ctx, (uint16_t)best, &ap)) break;
        used |= 1u << best;
        m = mt_tlv_wr_mark(w);
        e = mt_tlv_start(w, mt_tlv_anon(), MT_TLV_STRUCT);
        if (!e) e = mt_tlv_put_u(w, CTX(0), ap.security);
        if (!e) e = mt_tlv_put_bytes(w, CTX(1), mt_span_of(ap.ssid, ap.ssid_len > 32 ? 32 : ap.ssid_len));
        if (!e) e = mt_tlv_put_bytes(w, CTX(2), mt_span_of(ap.bssid, sizeof ap.bssid));
        if (!e) e = mt_tlv_put_u(w, CTX(3), ap.channel);
        if (!e) e = mt_tlv_put_u(w, CTX(4), ap.band);
        if (!e) e = mt_tlv_put_i(w, CTX(5), ap.rssi);
        if (!e) e = mt_tlv_end(w);
        if (e == MT_ERR_BUFFER_TOO_SMALL) { /* as many as fit */
            mt_tlv_wr_rollback(w, m);
            e = MT_OK;
            break;
        }
    }
    return e ? e : mt_tlv_end(w);
}

void mt_netcomm_scan_done(mt_netcomm *n, uint8_t status)
{
    mt_tlv_wr w;
    mt_span f;
    mt_err e;
    if (n->op.kind != OP_SCAN) return;
    if (n->op.aborted) status = MT_NET_UNKNOWN_ERROR;
    set_last(n, status, NULL, 0, NULL);
    mt_tlv_wr_init(&w, n->c.scratch);
    e = mt_tlv_put_u(&w, CTX(0), status);
    if (!e && status == MT_NET_OK) e = put_scan_results(n, &w);
    if (!e) e = mt_tlv_wr_done(&w, &f);
    if (e) { /* cannot happen with MT_NETCOMM_SCRATCH; answer without results */
        mt_tlv_wr_init(&w, n->c.scratch);
        mt_tlv_put_u(&w, CTX(0), MT_NET_UNKNOWN_ERROR);
        mt_tlv_wr_done(&w, &f);
    } else if (status == MT_NET_OK && n->op.crumb_set) {
        root_set_breadcrumb(n->c.root, n->op.crumb);
    }
    complete(n, C_SCAN_RESP, f);
}

uint32_t mt_netcomm_poll(mt_netcomm *n)
{
    uint32_t now;
    if (!n->op.kind) return UINT32_MAX;
    now = n->c.root->c.ops->now_ms(n->c.root->c.ctx);
    if (!mt_due(now, n->op.deadline)) return n->op.deadline - now;
    if (n->op.kind == OP_CONNECT) mt_netcomm_connect_done(n, MT_NET_OTHER_CONNECTION_FAILURE, NULL);
    else mt_netcomm_scan_done(n, MT_NET_UNKNOWN_ERROR);
    return UINT32_MAX;
}

/* ---- fail-safe hooks (mt_root_stage) ---- */

/* Persists the staged change; it stays staged (and `switched` stays set) until done() or undo(). */
static mt_err stage_commit(void *ctx, uint8_t fabric)
{
    mt_netcomm *n = ctx;
    mt_err e = MT_OK;
    (void)fabric;
    if (n->stage.kind == ST_SET)
        e = n->c.net->save(n->c.ctx, mt_span_of(n->stage.ssid, n->stage.ssid_len),
                           mt_span_of(n->stage.cred, n->stage.cred_len));
    else if (n->stage.kind == ST_REMOVE)
        e = n->c.net->erase(n->c.ctx);
    if (e) return e;
    n->persisted = n->stage.kind != ST_NONE;
    return MT_OK;
}

/* The fabric commit after stage_commit failed: the previous network goes back into storage. */
static void stage_undo(void *ctx)
{
    mt_netcomm *n = ctx;
    if (n->persisted && n->c.net->restore) n->c.net->restore(n->c.ctx);
    n->persisted = false;
}

static void stage_done(void *ctx)
{
    mt_netcomm *n = ctx;
    if (n->stage.kind != ST_NONE) changed(n, A_NETWORKS);
    mt_wipe(&n->stage, sizeof n->stage);
    n->stage.kind = ST_NONE;
    n->persisted = false;
    n->switched = false; /* the station is on what is now the persisted network */
}

/* Fail-safe expiry. It can run inside another invoke (ArmFailSafe(0), RemoveFabric, RevokeCommissioning), whose
 * response is being built in the IM buffer, so an operation in flight is not answered here: its deadline is moved
 * to now and mt_netcomm_poll answers it with a failure. */
static void stage_revert(void *ctx)
{
    mt_netcomm *n = ctx;
    bool had = n->stage.kind != ST_NONE;
    if (n->op.kind) {
        n->op.aborted = true;
        n->op.deadline = n->c.root->c.ops->now_ms(n->c.root->c.ctx);
    }
    mt_wipe(&n->stage, sizeof n->stage);
    n->stage.kind = ST_NONE;
    n->persisted = false;
    if (n->switched) {
        n->switched = false;
        n->c.net->revert(n->c.ctx);
        had = true;
    }
    if (had) changed(n, A_NETWORKS);
}

/* ---- init ---- */

mt_err mt_netcomm_init(mt_netcomm *n, const mt_netcomm_cfg *cfg)
{
    const mt_netctl_ops *o = cfg->net;
    mt_root_stage st;
    if (!o || !o->saved || !o->save || !o->erase || !o->connected || !o->connect || !o->revert || !o->scan ||
        !o->scan_result || !cfg->root || !cfg->bands || !cfg->scratch.p || cfg->scratch.cap < MT_NETCOMM_SCRATCH)
        return MT_ERR_INVALID;
    memset(n, 0, sizeof *n);
    n->c = *cfg;
    if (!n->c.scan_max_s) n->c.scan_max_s = DEFAULT_SCAN_S;
    if (!n->c.connect_max_s) n->c.connect_max_s = DEFAULT_CONNECT_S;
    n->enabled = true;
    n->cluster = (mt_dm_cluster){ .id = MT_NETCOMM_CLUSTER_ID, .features = FEATURE_WIFI, .revision = 2,
                                  .n_attrs = MT_DM_N(attrs), .n_cmds = MT_DM_N(cmds),
                                  .n_generated = MT_DM_N(generated), .attrs = attrs, .cmds = cmds,
                                  .generated = generated, .ops = &ops, .ctx = n };
    st.commit = stage_commit;
    st.undo = stage_undo;
    st.done = stage_done;
    st.revert = stage_revert;
    st.ctx = n;
    mt_root_set_stage(n->c.root, &st);
    return MT_OK;
}
