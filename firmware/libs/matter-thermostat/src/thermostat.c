/* Thermostat cluster (0x201, revision 6, FeatureMap HEAT) on libs/thermo, plus the endpoint wiring.
 * Spec source: Matter 1.3 data_model/1.3/clusters/Thermostat.xml; status codes for the checks the XML leaves
 * open follow chip v1.3-branch thermostat-server.cpp (PreAttributeChanged, SetpointRaiseLower).
 *
 * Mapping (thermo's units are tenths of a degree; Matter's are hundredths):
 *   LocalTemperature        = DP24 * 10, null until DP24 is reported or while a sensor fault (DP104) is set
 *   OccupiedHeatingSetpoint = thermo_target_tenths * 10 (the pending value while a write is in flight)
 *   SystemMode              = Off <-> DP1 = 0; with cfg.auto_mode Auto <-> smart/holiday; the rest reads Heat
 *   ThermostatRunningState  = bit 0 when thermo_current_state() says the relay is on */
#include "ts_priv.h"

#define V MT_IM_PRIV_VIEW
#define W MT_IM_ATTR_WRITABLE
#define F MT_IM_ATTR_FIXED

/* Attribute ids ascending (the order matter-im enumerates). */
static const mt_dm_attr_def attrs[] = {
    { MT_TSTAT_LOCAL_TEMPERATURE, 0, V, 0 },
    { MT_TSTAT_ABS_MIN_HEAT, F, V, 0 },
    { MT_TSTAT_ABS_MAX_HEAT, F, V, 0 },
    { MT_TSTAT_OCC_HEAT_SETPOINT, W, V, MT_IM_PRIV_OPERATE },
    { MT_TSTAT_MIN_HEAT, 0, V, 0 },        /* spec: writable (Manage); read-only here */
    { MT_TSTAT_MAX_HEAT, 0, V, 0 },
    { MT_TSTAT_CONTROL_SEQUENCE, W, V, MT_IM_PRIV_MANAGE },
    { MT_TSTAT_SYSTEM_MODE, W, V, MT_IM_PRIV_MANAGE },
    { MT_TSTAT_RUNNING_STATE, 0, V, 0 },
};
/* cfg.auto_mode: the same plus MinSetpointDeadBand (mandatory with AUTO; read-only, spec: writable by Manage) and a
 * fixed, read-only OccupiedCoolingSetpoint (Apple Home's Auto mapping reads it; see mt_thermostat.h). */
static const mt_dm_attr_def attrs_auto[] = {
    { MT_TSTAT_LOCAL_TEMPERATURE, 0, V, 0 },
    { MT_TSTAT_ABS_MIN_HEAT, F, V, 0 },
    { MT_TSTAT_ABS_MAX_HEAT, F, V, 0 },
    { MT_TSTAT_OCC_COOL_SETPOINT, 0, V, 0 },
    { MT_TSTAT_OCC_HEAT_SETPOINT, W, V, MT_IM_PRIV_OPERATE },
    { MT_TSTAT_MIN_HEAT, 0, V, 0 },
    { MT_TSTAT_MAX_HEAT, 0, V, 0 },
    { MT_TSTAT_MIN_DEADBAND, 0, V, 0 },
    { MT_TSTAT_CONTROL_SEQUENCE, W, V, MT_IM_PRIV_MANAGE },
    { MT_TSTAT_SYSTEM_MODE, W, V, MT_IM_PRIV_MANAGE },
    { MT_TSTAT_RUNNING_STATE, 0, V, 0 },
};
#define MIN_DEADBAND 25 /* 2.5 C (units of 0.1 C), the spec default */
static const mt_dm_cmd_def cmds[] = { { MT_TSTAT_CMD_SETPOINT_RAISE_LOWER, MT_IM_PRIV_OPERATE, false } };

/* Tenths (any int32 the MCU sends) to Matter's hundredths, saturating at the temperature type's range
 * (-273.15 .. 327.67 C), clamped before the * 10 so nothing overflows. */
#define TEMP_MIN (-27315)
static int16_t hundredths(int32_t tenths)
{
    return tenths > INT16_MAX / 10 ? INT16_MAX : tenths < TEMP_MIN / 10 ? TEMP_MIN : (int16_t)(tenths * 10);
}
static int32_t clamp_setpoint(int32_t v)
{
    return v < MT_THERMOSTAT_MIN_SETPOINT ? MT_THERMOSTAT_MIN_SETPOINT
         : v > MT_THERMOSTAT_MAX_SETPOINT ? MT_THERMOSTAT_MAX_SETPOINT : v;
}

void ts_view(const mt_thermostat *t, mt_thermostat_snap *s)
{
    const thermo *m = t->cfg.model;
    s->local_null = !m->s[THERMO_S_CURRENT].known || thermo_fault(m);
    s->local = s->local_null ? 0 : hundredths(thermo_current_tenths(m));
    s->setpoint = hundredths(thermo_target_tenths(m));
    s->mode = thermo_target_state(m) == THERMO_MODE_OFF                       ? MT_TSTAT_MODE_OFF
            : t->cfg.auto_mode && thermo_target_state(m) == THERMO_MODE_AUTO ? MT_TSTAT_MODE_AUTO
                                                                            : MT_TSTAT_MODE_HEAT;
    s->running = thermo_current_state(m) == THERMO_MODE_HEAT ? MT_TSTAT_RUNNING_HEAT : 0;
    s->schedule = thermo_target_state(m) == THERMO_MODE_AUTO;
}

static mt_err thermostat_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item,
                              mt_tlv_wr *w, mt_tlv_tag tag)
{
    const mt_thermostat *t = at->cl->ctx;
    mt_thermostat_snap s;
    (void)rc; (void)item;
    ts_view(t, &s);
    switch (attr) {
    case MT_TSTAT_LOCAL_TEMPERATURE: return s.local_null ? mt_tlv_put_null(w, tag) : mt_tlv_put_i(w, tag, s.local);
    case MT_TSTAT_ABS_MIN_HEAT:
    case MT_TSTAT_MIN_HEAT: return mt_tlv_put_i(w, tag, MT_THERMOSTAT_MIN_SETPOINT);
    case MT_TSTAT_ABS_MAX_HEAT:
    case MT_TSTAT_MAX_HEAT: return mt_tlv_put_i(w, tag, MT_THERMOSTAT_MAX_SETPOINT);
    case MT_TSTAT_OCC_HEAT_SETPOINT: return mt_tlv_put_i(w, tag, s.setpoint);
    case MT_TSTAT_MIN_DEADBAND:
        if (!t->cfg.auto_mode) return MT_ERR_NOT_FOUND;
        return mt_tlv_put_i(w, tag, MIN_DEADBAND);
    case MT_TSTAT_OCC_COOL_SETPOINT:
        if (!t->cfg.auto_mode) return MT_ERR_NOT_FOUND;
        return mt_tlv_put_i(w, tag, MT_THERMOSTAT_MAX_SETPOINT + 10 * MIN_DEADBAND);
    case MT_TSTAT_CONTROL_SEQUENCE: return mt_tlv_put_u(w, tag, MT_TSTAT_SEQ_HEATING_ONLY);
    case MT_TSTAT_SYSTEM_MODE: return mt_tlv_put_u(w, tag, s.mode);
    case MT_TSTAT_RUNNING_STATE: return mt_tlv_put_u(w, tag, s.running);
    default: return MT_ERR_NOT_FOUND;
    }
}

static void wrote(const mt_thermostat *t)
{
    if (t->cfg.on_write) t->cfg.on_write(t->cfg.ctx);
}

static mt_im_status thermostat_write(const mt_dm_at *at, const mt_im_wctx *wc, uint32_t attr, mt_im_wr_op op,
                                     mt_tlv_rd *val)
{
    mt_thermostat *t = at->cl->ctx;
    thermo *m = t->cfg.model;
    mt_im_status st;
    int64_t v;
    (void)wc;
    if (op != MT_IM_WR_VALUE) return MT_IM_INVALID_ACTION;
    if (attr != MT_TSTAT_OCC_HEAT_SETPOINT && attr != MT_TSTAT_CONTROL_SEQUENCE && attr != MT_TSTAT_SYSTEM_MODE)
        return MT_IM_UNSUPPORTED_WRITE;
    if ((st = ts_get_int(val, &v))) return st;
    switch (attr) {
    case MT_TSTAT_OCC_HEAT_SETPOINT:
        /* Rejected, not clamped (chip: MinHeatSetpointLimit..MaxHeatSetpointLimit). thermo rounds to 0.5 C. */
        if (v < MT_THERMOSTAT_MIN_SETPOINT || v > MT_THERMOSTAT_MAX_SETPOINT) return MT_IM_CONSTRAINT_ERROR;
        if (!thermo_set_target_c(m, (float)v / 100.0f, ts_now(t))) return MT_IM_FAILURE;
        t->snap.setpoint = hundredths(thermo_target_tenths(m)); /* the DM marks it dirty */
        break;
    case MT_TSTAT_SYSTEM_MODE:
        /* Off and Heat, plus Auto (the weekly program) with cfg.auto_mode; no COOL: chip answers anything
         * else with InvalidValue, which is CONSTRAINT_ERROR. Heat on a unit in its weekly schedule switches it to
         * hold (thermo). */
        if (v != MT_TSTAT_MODE_OFF && v != MT_TSTAT_MODE_HEAT && !(t->cfg.auto_mode && v == MT_TSTAT_MODE_AUTO))
            return MT_IM_CONSTRAINT_ERROR;
        if (!thermo_set_target_state(m, v == MT_TSTAT_MODE_OFF ? THERMO_MODE_OFF
                                        : v == MT_TSTAT_MODE_AUTO ? THERMO_MODE_AUTO : THERMO_MODE_HEAT, ts_now(t)))
            return MT_IM_FAILURE;
        t->snap.mode = (uint8_t)v;
        break;
    default: /* ControlSequenceOfOperation: fixed to HeatingOnly; the one valid write is a no-op */
        return v == MT_TSTAT_SEQ_HEATING_ONLY ? MT_IM_SUCCESS : MT_IM_CONSTRAINT_ERROR;
    }
    wrote(t);
    return MT_IM_SUCCESS;
}

/* SetpointRaiseLower (Operate): Heat or Both raise the heating setpoint by Amount * 0.1 C (Both = Heat here,
 * there is no cooling setpoint); Cool is INVALID_COMMAND (chip and rs-matter agree). The result is clamped to
 * the limits like chip does. thermo rounds to 0.5 C, so a raise/lower smaller than half a step would round
 * back to the current value: it moves one 0.5 C step in the requested direction instead, so the command
 * always does something unless the limit is reached. */
static mt_im_status raise_lower(const mt_dm_at *at, mt_tlv_rd *f)
{
    mt_thermostat *t = at->cl->ctx;
    thermo *m = t->cfg.model;
    int64_t mode = 0, amount = 0;
    mt_im_status st;
    int32_t base, want, next;
    if ((st = ts_int_field(f, 0, &mode)) || (st = ts_int_field(f, 1, &amount))) return st;
    if (mode < MT_TSTAT_RAISE_HEAT || mode > MT_TSTAT_RAISE_BOTH || amount < INT8_MIN || amount > INT8_MAX)
        return MT_IM_CONSTRAINT_ERROR;
    if (mode == MT_TSTAT_RAISE_COOL) return MT_IM_INVALID_COMMAND;

    base = hundredths(thermo_target_tenths(m));   /* the pending value, so repeated raises add up */
    want = clamp_setpoint(base + (int32_t)amount * 10);
    next = clamp_setpoint(((want + 25) / 50) * 50);
    if (amount != 0 && next == base) next = clamp_setpoint(base + (amount > 0 ? 50 : -50));
    if (next == base) return MT_IM_SUCCESS; /* amount 0, or already at the limit */
    if (!thermo_set_target_c(m, (float)next / 100.0f, ts_now(t))) return MT_IM_FAILURE;
    t->snap.setpoint = hundredths(thermo_target_tenths(m));
    mt_dm_changed(at->dm, at->ep->id, at->cl->id, MT_TSTAT_OCC_HEAT_SETPOINT);
    wrote(t);
    return MT_IM_SUCCESS;
}

static mt_im_status thermostat_invoke(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                                      mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    (void)s; (void)resp; (void)resp_cmd;
    if (cmd != MT_TSTAT_CMD_SETPOINT_RAISE_LOWER) return MT_IM_UNSUPPORTED_COMMAND;
    return raise_lower(at, fields);
}

static const mt_dm_ops ops = { thermostat_read, thermostat_write, thermostat_invoke };

void ts_thermostat_fill(mt_dm_cluster *c, mt_thermostat *t)
{
    bool a = t->cfg.auto_mode;
    *c = (mt_dm_cluster){ .id = MT_THERMOSTAT_CLUSTER_ID,
                          .features = MT_THERMOSTAT_FEATURE_HEAT | (a ? MT_THERMOSTAT_FEATURE_AUTO : 0),
                          .revision = MT_THERMOSTAT_REV,
                          .n_attrs = a ? MT_DM_N(attrs_auto) : MT_DM_N(attrs),
                          .n_cmds = MT_DM_N(cmds), .attrs = a ? attrs_auto : attrs, .cmds = cmds,
                          .ops = &ops, .ctx = t };
}

/* ---- endpoint, sync, tick ---- */

static const mt_dm_devtype k_type = { MT_THERMOSTAT_DEVICE_TYPE, MT_THERMOSTAT_DEVICE_REV };
static const mt_dm_devtype k_plugin = { MT_PLUGIN_UNIT_DEVICE_TYPE, MT_PLUGIN_UNIT_DEVICE_REV };

mt_err mt_thermostat_init(mt_thermostat *t, const mt_thermostat_cfg *cfg)
{
    if (!cfg->model || cfg->identify_type > MT_IDENTIFY_TYPE_ACTUATOR ||
        (cfg->auto_mode && !thermo_auto_supported(cfg->model)))
        return MT_ERR_INVALID;
    *t = (mt_thermostat){ .cfg = *cfg };
    ts_identify_fill(&t->identify, t);
    ts_thermostat_fill(&t->thermostat, t);
    t->clusters[0] = &t->identify;          /* ascending cluster ids: 0x03, 0x1D, 0x201 */
    t->clusters[1] = &mt_dm_descriptor;
    t->clusters[2] = &t->thermostat;
    t->types[0] = k_type;
    t->eps[0] = (mt_dm_endpoint){ .id = MT_THERMOSTAT_ENDPOINT, .n_types = 1, .n_clusters = 3, .n_clients = 0,
                                  .types = t->types, .clusters = t->clusters, .clients = NULL };
    t->n_eps = 1;
    if (thermo_auto_supported(cfg->model) && !cfg->auto_mode) {
        ts_onoff_fill(&t->onoff, t);
        t->sched_clusters[0] = &t->onoff;   /* ascending: 0x06, 0x1D */
        t->sched_clusters[1] = &mt_dm_descriptor;
        t->sched_types[0] = k_plugin;
        t->eps[1] = (mt_dm_endpoint){ .id = MT_SCHEDULE_ENDPOINT, .n_types = 1, .n_clusters = 2, .n_clients = 0,
                                      .types = t->sched_types, .clusters = t->sched_clusters, .clients = NULL };
        t->n_eps = 2;
    }
    ts_view(t, &t->snap);
    return MT_OK;
}

const mt_dm_endpoint *mt_thermostat_endpoint(const mt_thermostat *t) { return t->eps; }
uint8_t mt_thermostat_endpoint_count(const mt_thermostat *t) { return t->n_eps; }

void mt_thermostat_sync(mt_thermostat *t, mt_dm *dm)
{
    mt_thermostat_snap n, *o = &t->snap;
    ts_view(t, &n);
    if (n.local_null != o->local_null || n.local != o->local)
        mt_dm_changed(dm, MT_THERMOSTAT_ENDPOINT, MT_THERMOSTAT_CLUSTER_ID, MT_TSTAT_LOCAL_TEMPERATURE);
    if (n.setpoint != o->setpoint)
        mt_dm_changed(dm, MT_THERMOSTAT_ENDPOINT, MT_THERMOSTAT_CLUSTER_ID, MT_TSTAT_OCC_HEAT_SETPOINT);
    if (n.mode != o->mode)
        mt_dm_changed(dm, MT_THERMOSTAT_ENDPOINT, MT_THERMOSTAT_CLUSTER_ID, MT_TSTAT_SYSTEM_MODE);
    if (n.schedule != o->schedule && t->n_eps == 2)
        mt_dm_changed(dm, MT_SCHEDULE_ENDPOINT, MT_ONOFF_CLUSTER_ID, MT_ONOFF_ON_OFF);
    if (n.running != o->running)
        mt_dm_changed(dm, MT_THERMOSTAT_ENDPOINT, MT_THERMOSTAT_CLUSTER_ID, MT_TSTAT_RUNNING_STATE);
    *o = n;
}

uint32_t mt_thermostat_tick(mt_thermostat *t, mt_dm *dm)
{
    uint32_t now = ts_now(t), next;
    const thermo *m = t->cfg.model;
    thermo_tick(t->cfg.model, now);
    mt_thermostat_sync(t, dm);
    next = ts_identify_tick(t, dm, now);
    for (int i = 0; i < THERMO_S_COUNT; i++)   /* a pending hold needs thermo_tick to expire */
        if (m->s[i].pending && next > 500u) next = 500u;
    return next;
}
