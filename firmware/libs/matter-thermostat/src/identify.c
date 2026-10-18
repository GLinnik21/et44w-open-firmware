/* Identify cluster (0x03, revision 4, FeatureMap 0), Matter 1.3 data_model/1.3/clusters/Identify.xml.
 * IdentifyTime counts down once per second while non-zero; IdentifyType is configuration. The optional
 * TriggerEffect command (0x40) is not implemented. */
#include "ts_priv.h"

static const mt_dm_attr_def attrs[] = {
    { MT_IDENTIFY_TIME, MT_IM_ATTR_WRITABLE, MT_IM_PRIV_VIEW, MT_IM_PRIV_OPERATE },
    { MT_IDENTIFY_TYPE, 0, MT_IM_PRIV_VIEW, 0 }, /* no F quality in the 1.3 XML: the type may change */
};
static const mt_dm_cmd_def cmds[] = { { MT_IDENTIFY_CMD_IDENTIFY, MT_IM_PRIV_MANAGE, false } };

static mt_err identify_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item,
                            mt_tlv_wr *w, mt_tlv_tag tag)
{
    const mt_thermostat *t = at->cl->ctx;
    (void)rc; (void)item;
    switch (attr) {
    case MT_IDENTIFY_TIME: return mt_tlv_put_u(w, tag, t->identify_s);
    case MT_IDENTIFY_TYPE: return mt_tlv_put_u(w, tag, t->cfg.identify_type);
    default: return MT_ERR_NOT_FOUND;
    }
}

/* Sets IdentifyTime and tells the app on a start/stop edge. The caller handles dirty marking. */
static void set_time(mt_thermostat *t, uint16_t v)
{
    bool was = t->identify_s != 0;
    t->identify_s = v;
    t->identify_since = ts_now(t);
    if (was != (v != 0) && t->cfg.on_identify) t->cfg.on_identify(t->cfg.ctx, v != 0);
}

static mt_im_status identify_write(const mt_dm_at *at, const mt_im_wctx *wc, uint32_t attr, mt_im_wr_op op,
                                   mt_tlv_rd *val)
{
    mt_thermostat *t = at->cl->ctx;
    int64_t v;
    mt_im_status st;
    (void)wc;
    if (attr != MT_IDENTIFY_TIME) return MT_IM_UNSUPPORTED_WRITE;
    if (op != MT_IM_WR_VALUE) return MT_IM_INVALID_ACTION;
    if ((st = ts_get_int(val, &v))) return st;
    if (v < 0 || v > 0xFFFF) return MT_IM_CONSTRAINT_ERROR;
    set_time(t, (uint16_t)v);
    return MT_IM_SUCCESS; /* the DM marks the attribute dirty */
}

static mt_im_status identify_invoke(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                                    mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_thermostat *t = at->cl->ctx;
    mt_im_status st;
    int64_t v = 0;
    (void)s; (void)resp; (void)resp_cmd;
    if (cmd != MT_IDENTIFY_CMD_IDENTIFY) return MT_IM_UNSUPPORTED_COMMAND;
    if ((st = ts_int_field(fields, 0, &v))) return st;
    if (v < 0 || v > 0xFFFF) return MT_IM_CONSTRAINT_ERROR;
    set_time(t, (uint16_t)v);
    mt_dm_changed(at->dm, at->ep->id, at->cl->id, MT_IDENTIFY_TIME);
    return MT_IM_SUCCESS; /* DefaultSuccess */
}

static const mt_dm_ops ops = { identify_read, identify_write, identify_invoke };

void ts_identify_fill(mt_dm_cluster *c, void *ctx)
{
    *c = (mt_dm_cluster){ .id = MT_IDENTIFY_CLUSTER_ID, .features = 0, .revision = MT_IDENTIFY_REV,
                          .n_attrs = MT_DM_N(attrs), .n_cmds = MT_DM_N(cmds),
                          .attrs = attrs, .cmds = cmds, .ops = &ops, .ctx = ctx };
}

uint32_t ts_identify_tick(mt_thermostat *t, mt_dm *dm, uint32_t now)
{
    uint32_t steps;
    if (!t->identify_s) return UINT32_MAX;
    steps = (uint32_t)(now - t->identify_since) / 1000u;
    if (steps) {
        t->identify_s = steps >= t->identify_s ? 0 : (uint16_t)(t->identify_s - steps);
        t->identify_since += steps * 1000u;
        mt_dm_changed(dm, MT_THERMOSTAT_ENDPOINT, MT_IDENTIFY_CLUSTER_ID, MT_IDENTIFY_TIME);
        if (!t->identify_s) {
            if (t->cfg.on_identify) t->cfg.on_identify(t->cfg.ctx, false);
            return UINT32_MAX;
        }
    }
    return 1000u - (uint32_t)(now - t->identify_since);
}
