/* The commissioning context shared by the endpoint-0 commissioning clusters: init, fail-safe timer, helpers.
 * The cluster handlers are in general_commissioning.c, operational_credentials.c, access_control.c and
 * group_key_management.c. */
#include "root_priv.h"

bool root_session(mt_root *r, uint16_t session, mt_root_session *out)
{
    memset(out, 0, sizeof *out);
    return r->c.ops->session(r->c.ctx, session, out);
}

void root_changed(mt_root *r, uint32_t cluster, uint32_t attr)
{
    if (r->dm) mt_dm_changed(r->dm, 0, cluster, attr);
}

/* ---- RegulatoryConfig record: struct { 1: RegulatoryLocationTypeEnum } ---- */

static void load_regulatory(mt_root *r)
{
    uint8_t buf[8];
    size_t n = 0;
    mt_tlv_rd rd;
    uint8_t v;
    r->regulatory = r->c.location_cap == MT_REG_INDOOR_OUTDOOR ? MT_REG_INDOOR : r->c.location_cap;
    if (!r->c.kv || r->c.kv->get(r->c.kv->ctx, r->c.kv_key, mt_buf_of(buf, sizeof buf), &n)) return;
    mt_tlv_rd_init(&rd, mt_span_of(buf, n));
    if (mt_tlv_next(&rd) || rd.type != MT_TLV_STRUCT || mt_tlv_enter(&rd) || mt_tlv_find_ctx(&rd, 1) ||
        mt_tlv_get_u8(&rd, &v) || v > MT_REG_INDOOR_OUTDOOR)
        return; /* absent or corrupt: keep the default */
    r->regulatory = v;
}

mt_err root_save_regulatory(mt_root *r, uint8_t v)
{
    uint8_t buf[8];
    mt_tlv_wr w;
    mt_span rec;
    if (!r->c.kv) return MT_OK;
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_err e = mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_u(&w, CTX(1), v);
    if (!e) e = mt_tlv_end(&w);
    if (!e) e = mt_tlv_wr_done(&w, &rec);
    if (!e) e = r->c.kv->set(r->c.kv->ctx, r->c.kv_key, rec);
    if (!e) return r->c.kv->finish(r->c.kv->ctx, true);
    r->c.kv->finish(r->c.kv->ctx, false);
    return e;
}

/* ---- init ---- */

mt_err mt_root_init(mt_root *r, const mt_root_cfg *cfg)
{
    const mt_root_ops *o = cfg->ops;
    if (!o || !o->now_ms || !o->session || !o->adopt_fabric || !o->window_open || !cfg->fabrics || !cfg->rng ||
        !cfg->creds || !cfg->creds->sign || !cfg->creds->dac.len || !cfg->creds->pai.len || !cfg->creds->cd.len ||
        !cfg->scratch.p || cfg->scratch.cap < MT_ROOT_SCRATCH || cfg->location_cap > MT_REG_INDOOR_OUTDOOR)
        return MT_ERR_INVALID;
    memset(r, 0, sizeof *r);
    r->c = *cfg;
    load_regulatory(r);
    root_gencomm_init(r);
    root_opcreds_init(r);
    root_acl_init(r);
    root_gkm_init(r);
    root_timesync_init(r);
    return MT_OK;
}

void mt_root_bind_dm(mt_root *r, mt_dm *dm) { r->dm = dm; }

void mt_root_set_stage(mt_root *r, const mt_root_stage *st) { r->stage = *st; }

void root_set_breadcrumb(mt_root *r, uint64_t v)
{
    r->breadcrumb = v;
    root_changed(r, MT_GENCOMM_CLUSTER_ID, 0 /* Breadcrumb */);
}

/* ---- fail-safe expiry (11.10.7.2: on expiry the node rolls back everything done under the fail-safe) ---- */

void mt_root_failsafe_expire(mt_root *r)
{
    uint8_t fabric = r->fs.fabric, flags = r->fs.flags;
    uint16_t session = r->fs.session;
    if (!r->fs.armed) return;
    mt_fabric_abort(r->c.fabrics); /* pending fabric / update, staged root and operational key */
    memset(&r->fs, 0, sizeof r->fs);
    r->breadcrumb = 0;
    root_changed(r, MT_GENCOMM_CLUSTER_ID, 0 /* Breadcrumb */);
    if (flags & (MT_FS_ADD_TRC | MT_FS_ADD_NOC | MT_FS_UPDATE_NOC)) {
        root_changed(r, MT_OPCREDS_CLUSTER_ID, MT_IM_WILD_ID);
        root_changed(r, MT_ACL_CLUSTER_ID, MT_IM_WILD_ID);
    }
    if (r->stage.revert) r->stage.revert(r->stage.ctx);
    root_event(r, MT_ROOT_EV_FAILSAFE_EXPIRED, fabric, session, flags);
}

void root_fs_arm(mt_root *r, uint8_t fabric, uint16_t session, uint16_t secs)
{
    uint32_t now = r->c.ops->now_ms(r->c.ctx), end;
    if (!r->fs.armed) {
        memset(&r->fs, 0, sizeof r->fs);
        r->fs.armed = true;
        r->fs.fabric = fabric;
        r->fs.limit = now + MT_ROOT_FAILSAFE_MAX_CUMULATIVE_S * 1000u;
    }
    r->fs.session = session;
    end = now + secs * 1000u;
    r->fs.deadline = (int32_t)(end - r->fs.limit) > 0 ? r->fs.limit : end;
}

bool mt_root_failsafe_arm(mt_root *r, uint8_t fabric, uint16_t session, uint16_t secs)
{
    if (r->fs.armed || !secs) return false;
    root_fs_arm(r, fabric, session, secs);
    return true;
}

uint32_t mt_root_poll(mt_root *r)
{
    uint32_t now;
    root_time_advance(r);
    if (!r->fs.armed) return UINT32_MAX;
    now = r->c.ops->now_ms(r->c.ctx);
    if (mt_due(now, r->fs.deadline)) {
        mt_root_failsafe_expire(r);
        return UINT32_MAX;
    }
    return r->fs.deadline - now;
}
