/* Basic Information cluster (0x28), see mt_root.h. */
#include <string.h>
#include "mt_root.h"

#define CTX(n) mt_tlv_ctx(n)
#define FX MT_IM_ATTR_FIXED
#define V MT_IM_PRIV_VIEW

static const mt_dm_attr_def attrs[] = {
    { MT_BASIC_DATA_MODEL_REVISION, FX, V, 0 },
    { MT_BASIC_VENDOR_NAME, FX, V, 0 },
    { MT_BASIC_VENDOR_ID, FX, V, 0 },
    { MT_BASIC_PRODUCT_NAME, FX, V, 0 },
    { MT_BASIC_PRODUCT_ID, FX, V, 0 },
    { MT_BASIC_NODE_LABEL, MT_IM_ATTR_WRITABLE, V, MT_IM_PRIV_MANAGE },
    { MT_BASIC_LOCATION, MT_IM_ATTR_WRITABLE, V, MT_IM_PRIV_ADMINISTER },
    { MT_BASIC_HARDWARE_VERSION, FX, V, 0 },
    { MT_BASIC_HARDWARE_VERSION_STRING, FX, V, 0 },
    { MT_BASIC_SOFTWARE_VERSION, FX, V, 0 },
    { MT_BASIC_SOFTWARE_VERSION_STRING, FX, V, 0 },
    { MT_BASIC_SERIAL_NUMBER, FX, V, 0 },
    { MT_BASIC_UNIQUE_ID, FX, V, 0 },
    { MT_BASIC_CAPABILITY_MINIMA, FX, V, 0 },
    { MT_BASIC_SPECIFICATION_VERSION, FX, V, 0 },
    { MT_BASIC_MAX_PATHS_PER_INVOKE, FX, V, 0 },
};
static const uint32_t events[] = { MT_BASIC_EVENT_STARTUP };

static mt_err put_str(mt_tlv_wr *w, mt_tlv_tag tag, const char *s)
{
    return mt_tlv_put_utf8(w, tag, s, strlen(s));
}

static mt_err basic_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                         mt_tlv_tag tag)
{
    const mt_basic *b = at->cl->ctx;
    const mt_basic_cfg *c = b->cfg;
    (void)rc; (void)item;
    switch (attr) {
    case MT_BASIC_DATA_MODEL_REVISION: return mt_tlv_put_u(w, tag, MT_BASIC_DATA_MODEL_REV);
    case MT_BASIC_VENDOR_NAME: return put_str(w, tag, c->vendor_name);
    case MT_BASIC_VENDOR_ID: return mt_tlv_put_u(w, tag, c->vendor_id);
    case MT_BASIC_PRODUCT_NAME: return put_str(w, tag, c->product_name);
    case MT_BASIC_PRODUCT_ID: return mt_tlv_put_u(w, tag, c->product_id);
    case MT_BASIC_NODE_LABEL: return put_str(w, tag, b->label);
    case MT_BASIC_LOCATION: return put_str(w, tag, b->location);
    case MT_BASIC_HARDWARE_VERSION: return mt_tlv_put_u(w, tag, c->hardware_version);
    case MT_BASIC_HARDWARE_VERSION_STRING: return put_str(w, tag, c->hardware_version_str);
    case MT_BASIC_SOFTWARE_VERSION: return mt_tlv_put_u(w, tag, c->software_version);
    case MT_BASIC_SOFTWARE_VERSION_STRING: return put_str(w, tag, c->software_version_str);
    case MT_BASIC_SERIAL_NUMBER: return put_str(w, tag, c->serial_number);
    case MT_BASIC_UNIQUE_ID: return put_str(w, tag, c->unique_id);
    case MT_BASIC_CAPABILITY_MINIMA: {
        mt_tlv_mark m = mt_tlv_wr_mark(w);
        mt_err e = mt_tlv_start(w, tag, MT_TLV_STRUCT);
        if (!e) e = mt_tlv_put_u(w, CTX(0), c->case_sessions_per_fabric);
        if (!e) e = mt_tlv_put_u(w, CTX(1), c->subscriptions_per_fabric);
        if (!e) e = mt_tlv_end(w);
        if (e) mt_tlv_wr_rollback(w, m);
        return e;
    }
    case MT_BASIC_SPECIFICATION_VERSION: return mt_tlv_put_u(w, tag, MT_BASIC_SPEC_VERSION);
    case MT_BASIC_MAX_PATHS_PER_INVOKE: return mt_tlv_put_u(w, tag, c->max_paths_per_invoke);
    default: return MT_ERR_NOT_FOUND;
    }
}

/* ---- persistence: one record, struct { 1: label, 2: location } ---- */

static mt_err save(const mt_basic *b, const char *label, const char *loc)
{
    uint8_t buf[64];
    mt_tlv_wr w;
    mt_span rec;
    if (!b->kv) return MT_OK;
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_err e = mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    if (!e) e = put_str(&w, CTX(1), label);
    if (!e) e = put_str(&w, CTX(2), loc);
    if (!e) e = mt_tlv_end(&w);
    if (!e) e = mt_tlv_wr_done(&w, &rec);
    if (!e) e = b->kv->set(b->kv->ctx, b->kv_key, rec);
    if (!e) e = b->kv->finish(b->kv->ctx, true);
    else b->kv->finish(b->kv->ctx, false);
    return e;
}

static void load(mt_basic *b)
{
    uint8_t buf[64];
    size_t n = 0;
    mt_tlv_rd r;
    char label[MT_BASIC_LABEL_MAX + 1] = "", loc[MT_BASIC_LOCATION_LEN + 1] = "";
    bool has_label = false, has_loc = false;
    mt_err e;
    if (!b->kv || b->kv->get(b->kv->ctx, b->kv_key, mt_buf_of(buf, sizeof buf), &n)) return;
    mt_tlv_rd_init(&r, mt_span_of(buf, n));
    if (mt_tlv_next(&r) || r.type != MT_TLV_STRUCT || mt_tlv_enter(&r)) return;
    while (!(e = mt_tlv_next(&r))) {
        mt_span s;
        if (mt_tlv_get_utf8(&r, &s)) return;
        if (mt_tlv_is_ctx(&r, 1) && s.len <= MT_BASIC_LABEL_MAX) {
            memcpy(label, s.p, s.len);
            label[s.len] = 0;
            has_label = true;
        } else if (mt_tlv_is_ctx(&r, 2) && s.len == MT_BASIC_LOCATION_LEN) {
            memcpy(loc, s.p, s.len);
            loc[s.len] = 0;
            has_loc = true;
        }
    }
    if (e != MT_ERR_NOT_FOUND || !has_label || !has_loc) return; /* corrupt: keep the defaults */
    memcpy(b->label, label, sizeof label);
    memcpy(b->location, loc, sizeof loc);
}

static mt_im_status basic_write(const mt_dm_at *at, const mt_im_wctx *wc, uint32_t attr, mt_im_wr_op op,
                                mt_tlv_rd *val)
{
    mt_basic *b = at->cl->ctx;
    char label[MT_BASIC_LABEL_MAX + 1], loc[MT_BASIC_LOCATION_LEN + 1];
    mt_span s;
    (void)wc;
    if (op != MT_IM_WR_VALUE) return MT_IM_INVALID_ACTION;
    if (attr != MT_BASIC_NODE_LABEL && attr != MT_BASIC_LOCATION) return MT_IM_UNSUPPORTED_WRITE;
    if (mt_tlv_get_utf8(val, &s)) return MT_IM_INVALID_DATA_TYPE;
    if (s.len && memchr(s.p, 0, s.len)) return MT_IM_CONSTRAINT_ERROR; /* kept as C strings: a NUL would truncate them */
    memcpy(label, b->label, sizeof label);
    memcpy(loc, b->location, sizeof loc);
    if (attr == MT_BASIC_NODE_LABEL) {
        if (s.len > MT_BASIC_LABEL_MAX) return MT_IM_CONSTRAINT_ERROR;
        memcpy(label, s.p, s.len);
        label[s.len] = 0;
    } else {
        if (s.len != MT_BASIC_LOCATION_LEN) return MT_IM_CONSTRAINT_ERROR;
        memcpy(loc, s.p, s.len);
        loc[s.len] = 0;
    }
    if (save(b, label, loc)) return MT_IM_FAILURE; /* RAM keeps the old value */
    memcpy(b->label, label, sizeof label);
    memcpy(b->location, loc, sizeof loc);
    return MT_IM_SUCCESS;
}

static const mt_dm_ops ops = { basic_read, basic_write, NULL };

mt_err mt_basic_set_location(mt_basic *b, const char *cc, size_t len)
{
    char loc[MT_BASIC_LOCATION_LEN + 1];
    if (len != MT_BASIC_LOCATION_LEN || memchr(cc, 0, len)) return MT_ERR_INVALID;
    memcpy(loc, cc, len);
    loc[len] = 0;
    if (!strcmp(loc, b->location)) return MT_OK;
    mt_err e = save(b, b->label, loc);
    if (!e) memcpy(b->location, loc, sizeof loc);
    return e;
}

mt_err mt_basic_init(mt_basic *b, const mt_basic_cfg *cfg, const mt_kv_ops *kv, uint16_t kv_key)
{
    if (!cfg->vendor_name || !cfg->product_name || !cfg->hardware_version_str || !cfg->software_version_str ||
        !cfg->serial_number || !cfg->unique_id) return MT_ERR_INVALID;
    memset(b, 0, sizeof *b);
    b->cfg = cfg;
    b->kv = kv;
    b->kv_key = kv_key;
    memcpy(b->location, "XX", sizeof b->location);
    load(b);
    b->cluster = (mt_dm_cluster){ .id = MT_BASIC_CLUSTER_ID, .features = 0, .revision = 3, .n_attrs = MT_DM_N(attrs),
                                  .n_events = MT_DM_N(events), .attrs = attrs, .events = events, .ops = &ops,
                                  .ctx = b };
    return MT_OK;
}

size_t mt_basic_startup_fields(const mt_basic *b, uint8_t *out, size_t cap)
{
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, mt_buf_of(out, cap));
    if (mt_tlv_put_u(&w, CTX(0), b->cfg->software_version)) return 0;
    return w.len;
}
