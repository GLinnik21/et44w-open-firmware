/* Time Synchronization cluster (0x38, spec 1.3 section 11.17, revision 2) without features: UTCTime, Granularity,
 * TimeSource and SetUTCTime. No TimeZone/NTP/TrustedTimeSource features (conformance of every other attribute and
 * command depends on a feature). Ids, access and conformance from the 1.3 cluster IDL (TimeSynchronization.xml);
 * the TimeFailure event (3, mandatory) is declared but never emitted.
 *
 * The time is kept as a Matter-epoch microsecond value plus the node-clock reading it belongs to (mt_root_time),
 * so it needs no RTC and no extra tick: every read and mt_root_poll() fold the elapsed clock time in. */
#include "root_priv.h"

enum { A_UTC_TIME = 0, A_GRANULARITY = 1, A_TIME_SOURCE = 2 };
enum { C_SET_UTC = 0 };
enum { EV_TIME_FAILURE = 3 };

#define V MT_IM_PRIV_VIEW

static const mt_dm_attr_def attrs[] = {
    { A_UTC_TIME, MT_IM_ATTR_OMITTED, V, 0 },   /* quality X C: nullable, changes omitted from reports */
    { A_GRANULARITY, 0, V, 0 },
    { A_TIME_SOURCE, 0, V, 0 },
};
static const mt_dm_cmd_def cmds[] = { { C_SET_UTC, MT_IM_PRIV_ADMINISTER, false } };
static const uint32_t events[] = { EV_TIME_FAILURE };

void root_time_advance(mt_root *r)
{
    mt_root_time *t = &r->time;
    uint32_t now = r->c.ops->now_ms(r->c.ctx);
    if (t->valid) t->us += (uint64_t)(uint32_t)(now - t->ref_ms) * 1000u;
    t->ref_ms = now;
}

bool mt_root_utc_us(mt_root *r, uint64_t *matter_us)
{
    root_time_advance(r);
    if (!r->time.valid) return false;
    *matter_us = r->time.us;
    return true;
}

uint32_t mt_root_utc_now(mt_root *r)
{
    uint64_t us, s;
    if (!mt_root_utc_us(r, &us)) return 0;
    s = us / 1000000u;
    return s > UINT32_MAX ? UINT32_MAX : (uint32_t)s;
}

static void time_store(mt_root *r, uint64_t us, uint8_t gran, uint8_t src, bool local)
{
    r->time.valid = true;
    r->time.local = local;
    r->time.us = us;
    r->time.ref_ms = r->c.ops->now_ms(r->c.ctx);
    r->time.granularity = gran;
    r->time.source = src;
    root_changed(r, MT_TIMESYNC_CLUSTER_ID, MT_IM_WILD_ID);
}

mt_err mt_root_set_utc(mt_root *r, uint64_t matter_us, uint8_t granularity, uint8_t source)
{
    if (granularity < MT_TIME_GRAN_MINUTES || granularity > MT_TIME_GRAN_US || source > MT_TIME_SRC_MAX)
        return MT_ERR_INVALID;
    time_store(r, matter_us, granularity, source, true);
    return MT_OK;
}

static mt_err ts_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                      mt_tlv_tag tag)
{
    mt_root *r = at->cl->ctx;
    uint64_t us;
    (void)rc; (void)item;
    switch (attr) {
    case A_UTC_TIME: return mt_root_utc_us(r, &us) ? mt_tlv_put_u(w, tag, us) : mt_tlv_put_null(w, tag);
    case A_GRANULARITY: return mt_tlv_put_u(w, tag, r->time.valid ? r->time.granularity : MT_TIME_GRAN_NONE);
    case A_TIME_SOURCE: return mt_tlv_put_u(w, tag, r->time.valid ? r->time.source : MT_TIME_SRC_NONE);
    default: return MT_ERR_NOT_FOUND;
    }
}

/* 11.17.7.1 SetUTCTime {0: UTCTime, 1: Granularity, 2: TimeSource?}. Granularity None is not a settable value and
 * the enums are range checked (CONSTRAINT_ERROR). A missing TimeSource is recorded as Admin: the time came from a
 * commissioner over this command. The node refuses (cluster status TimeNotAccepted) only a coarser time than one it
 * took from its own source (SNTP/RTC through mt_root_set_utc); another administrator's time is replaced. This is
 * our reading of 11.17.7.1 ("the node MAY refuse"): chip v1.3 source was not available to check the exact rule. */
static mt_im_status set_utc(mt_root *r, mt_tlv_rd *f)
{
    mt_tlv_rd x;
    uint64_t us;
    uint8_t gran, src = MT_TIME_SRC_ADMIN;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_u64(&x, &us) || mt_im_field(f, 1, &x) || mt_tlv_get_u8(&x, &gran))
        return MT_IM_INVALID_COMMAND;
    if (!mt_im_field(f, 2, &x) && mt_tlv_get_u8(&x, &src)) return MT_IM_INVALID_COMMAND;
    if (gran < MT_TIME_GRAN_MINUTES || gran > MT_TIME_GRAN_US || src > MT_TIME_SRC_MAX) return MT_IM_CONSTRAINT_ERROR;
    if (r->time.valid && r->time.local && gran < r->time.granularity)
        return MT_IM_CST(MT_TIME_CST_NOT_ACCEPTED);
    time_store(r, us, gran, src, false);
    if (r->c.ops->utc_set) r->c.ops->utc_set(r->c.ctx, us, gran, src);
    return MT_IM_SUCCESS;
}

static mt_im_status ts_invoke(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                              mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    (void)s; (void)resp; (void)resp_cmd;
    return cmd == C_SET_UTC ? set_utc(at->cl->ctx, fields) : MT_IM_UNSUPPORTED_COMMAND;
}

static const mt_dm_ops ops = { ts_read, NULL, ts_invoke };

void root_timesync_init(mt_root *r)
{
    r->timesync = (mt_dm_cluster){ .id = MT_TIMESYNC_CLUSTER_ID, .revision = 2, .n_attrs = MT_DM_N(attrs),
                                   .n_cmds = MT_DM_N(cmds), .n_events = MT_DM_N(events), .attrs = attrs,
                                   .cmds = cmds, .events = events, .ops = &ops, .ctx = r };
}
