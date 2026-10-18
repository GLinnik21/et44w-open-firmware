/* On/Off cluster (0x0006, revision 6, FeatureMap 0) on endpoint 2: the thermostat's weekly program.
 * Spec source: Matter 1.3 data_model/1.3/clusters/OnOff.xml; device type On/Off Plug-in Unit (0x010A).
 *
 * OnOff = thermo_target_state() is Auto (DP1 on and DP2 smart or holiday).
 *   On  -> thermo Auto: DP1 = 1 and DP2 = smart (holiday is kept). Turns a switched-off thermostat on.
 *   Off -> thermo Heat (DP2 = hold, the setpoint stays) if the program was running; otherwise nothing, so
 *          "Off" never switches the heating off or on.
 * Deviations: the device type's mandatory Identify and Groups clusters are absent on this endpoint, and the
 * OnOff attribute is not writable (spec: read-only too; Home uses the commands). */
#include "ts_priv.h"

static const mt_dm_attr_def attrs[] = { { MT_ONOFF_ON_OFF, 0, MT_IM_PRIV_VIEW, 0 } };
static const mt_dm_cmd_def cmds[] = { { MT_ONOFF_CMD_OFF, MT_IM_PRIV_OPERATE, false },
                                      { MT_ONOFF_CMD_ON, MT_IM_PRIV_OPERATE, false },
                                      { MT_ONOFF_CMD_TOGGLE, MT_IM_PRIV_OPERATE, false } };

static bool running(const mt_thermostat *t) { return thermo_target_state(t->cfg.model) == THERMO_HK_AUTO; }

static mt_err onoff_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                         mt_tlv_tag tag)
{
    (void)rc; (void)item;
    if (attr != MT_ONOFF_ON_OFF) return MT_ERR_NOT_FOUND;
    return mt_tlv_put_bool(w, tag, running(at->cl->ctx));
}

static mt_im_status onoff_write(const mt_dm_at *at, const mt_im_wctx *wc, uint32_t attr, mt_im_wr_op op,
                                mt_tlv_rd *val)
{
    (void)at; (void)wc; (void)attr; (void)op; (void)val;
    return MT_IM_UNSUPPORTED_WRITE;
}

static mt_im_status onoff_invoke(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                                 mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_thermostat *t = at->cl->ctx;
    bool want;
    (void)s; (void)fields; (void)resp; (void)resp_cmd;
    switch (cmd) {
    case MT_ONOFF_CMD_OFF: want = false; break;
    case MT_ONOFF_CMD_ON: want = true; break;
    case MT_ONOFF_CMD_TOGGLE: want = !running(t); break;
    default: return MT_IM_UNSUPPORTED_COMMAND;
    }
    if (want == running(t)) return MT_IM_SUCCESS;
    if (!thermo_set_target_state(t->cfg.model, want ? THERMO_HK_AUTO : THERMO_HK_HEAT, ts_now(t)))
        return MT_IM_FAILURE;
    /* The pending model value changed: endpoint 1's SystemMode may too. sync reports both. */
    if (t->cfg.on_write) t->cfg.on_write(t->cfg.ctx);
    mt_thermostat_sync(t, at->dm);
    return MT_IM_SUCCESS;
}

static const mt_dm_ops ops = { onoff_read, onoff_write, onoff_invoke };

void ts_onoff_fill(mt_dm_cluster *c, void *ctx)
{
    *c = (mt_dm_cluster){ .id = MT_ONOFF_CLUSTER_ID, .features = 0, .revision = MT_ONOFF_REV,
                          .n_attrs = MT_DM_N(attrs), .n_cmds = MT_DM_N(cmds),
                          .attrs = attrs, .cmds = cmds, .ops = &ops, .ctx = ctx };
}
