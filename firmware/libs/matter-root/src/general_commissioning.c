/* General Commissioning cluster (0x30, spec 1.3 section 11.10), see mt_root_comm.h.
 * Command rules as in connectedhomeip v1.3 general-commissioning-server.cpp. */
#include "root_priv.h"

enum { A_BREADCRUMB = 0, A_BASIC_INFO = 1, A_REGULATORY = 2, A_LOCATION_CAP = 3, A_CONCURRENT = 4 };
enum { C_ARM = 0, C_ARM_RESP = 1, C_SET_REG = 2, C_SET_REG_RESP = 3, C_COMPLETE = 4, C_COMPLETE_RESP = 5 };

#define FX MT_IM_ATTR_FIXED
#define V MT_IM_PRIV_VIEW
#define ADM MT_IM_PRIV_ADMINISTER

static const mt_dm_attr_def attrs[] = {
    { A_BREADCRUMB, MT_IM_ATTR_WRITABLE, V, ADM },
    { A_BASIC_INFO, FX, V, 0 },
    { A_REGULATORY, 0, V, 0 },
    { A_LOCATION_CAP, FX, V, 0 },
    { A_CONCURRENT, FX, V, 0 },
};
static const mt_dm_cmd_def cmds[] = { { C_ARM, ADM, false }, { C_SET_REG, ADM, false }, { C_COMPLETE, ADM, false } };
static const uint32_t generated[] = { C_ARM_RESP, C_SET_REG_RESP, C_COMPLETE_RESP };

static mt_err gc_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                      mt_tlv_tag tag)
{
    const mt_root *r = at->cl->ctx;
    (void)rc; (void)item;
    switch (attr) {
    case A_BREADCRUMB: return mt_tlv_put_u(w, tag, r->breadcrumb);
    case A_BASIC_INFO: {
        mt_tlv_mark m = mt_tlv_wr_mark(w);
        mt_err e = mt_tlv_start(w, tag, MT_TLV_STRUCT);
        if (!e) e = mt_tlv_put_u(w, CTX(0), MT_ROOT_FAILSAFE_EXPIRY_S);
        if (!e) e = mt_tlv_put_u(w, CTX(1), MT_ROOT_FAILSAFE_MAX_CUMULATIVE_S);
        if (!e) e = mt_tlv_end(w);
        if (e) mt_tlv_wr_rollback(w, m);
        return e;
    }
    case A_REGULATORY: return mt_tlv_put_u(w, tag, r->regulatory);
    case A_LOCATION_CAP: return mt_tlv_put_u(w, tag, r->c.location_cap);
    case A_CONCURRENT: return mt_tlv_put_bool(w, tag, true); /* the module stays on its network while commissioned */
    default: return MT_ERR_NOT_FOUND;
    }
}

static mt_im_status gc_write(const mt_dm_at *at, const mt_im_wctx *wc, uint32_t attr, mt_im_wr_op op, mt_tlv_rd *val)
{
    mt_root *r = at->cl->ctx;
    uint64_t v;
    (void)wc;
    if (attr != A_BREADCRUMB) return MT_IM_UNSUPPORTED_WRITE;
    if (op != MT_IM_WR_VALUE) return MT_IM_INVALID_ACTION;
    if (mt_tlv_get_u64(val, &v)) return MT_IM_INVALID_DATA_TYPE;
    r->breadcrumb = v;
    return MT_IM_SUCCESS;
}

/* {0: CommissioningErrorEnum, 1: DebugText} -- DebugText is mandatory in all three responses (1.3 IDL). */
static mt_im_status respond(mt_tlv_wr *resp, uint32_t *resp_cmd, uint32_t cmd, uint8_t code)
{
    if (mt_tlv_put_u(resp, CTX(0), code) || mt_tlv_put_utf8(resp, CTX(1), "", 0)) return MT_IM_RESOURCE_EXHAUSTED;
    *resp_cmd = cmd;
    return MT_IM_SUCCESS;
}

/* 11.10.7.2 */
static mt_im_status arm_fail_safe(mt_root *r, const mt_im_subject *s, mt_tlv_rd *f,
                                  mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_tlv_rd x;
    uint16_t secs;
    uint64_t crumb;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_u16(&x, &secs) || mt_im_field(f, 1, &x) || mt_tlv_get_u64(&x, &crumb))
        return MT_IM_INVALID_COMMAND;
    /* Armed for another fabric, or a CASE session trying to take a disarmed fail-safe while a commissioning
     * window is open (it is reserved for the commissioner on that window). */
    if ((r->fs.armed && r->fs.fabric != s->fabric) ||
        (!r->fs.armed && s->auth == MT_IM_AUTH_CASE && r->c.ops->window_open(r->c.ctx)))
        return respond(resp, resp_cmd, C_ARM_RESP, MT_COMM_BUSY_WITH_OTHER_ADMIN);
    if (secs == 0) { /* expire now; the breadcrumb is reset by the expiry, not set */
        mt_root_failsafe_expire(r);
        return respond(resp, resp_cmd, C_ARM_RESP, MT_COMM_OK);
    }
    root_fs_arm(r, s->fabric, s->session, secs);
    root_set_breadcrumb(r, crumb);
    return respond(resp, resp_cmd, C_ARM_RESP, MT_COMM_OK);
}

/* 11.10.7.4 */
static mt_im_status set_regulatory(mt_root *r, const mt_dm_at *at, mt_tlv_rd *f, mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_tlv_rd x;
    uint8_t loc;
    mt_span cc;
    uint64_t crumb;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_u8(&x, &loc) || mt_im_field(f, 1, &x) || mt_tlv_get_utf8(&x, &cc) ||
        mt_im_field(f, 2, &x) || mt_tlv_get_u64(&x, &crumb))
        return MT_IM_INVALID_COMMAND;
    if (cc.len != MT_BASIC_LOCATION_LEN || memchr(cc.p, 0, cc.len)) return MT_IM_CONSTRAINT_ERROR;
    if (loc > MT_REG_INDOOR_OUTDOOR || (r->c.location_cap != MT_REG_INDOOR_OUTDOOR && loc != r->c.location_cap))
        return respond(resp, resp_cmd, C_SET_REG_RESP, MT_COMM_VALUE_OUTSIDE_RANGE);
    if (r->c.basic) {
        if (mt_basic_set_location(r->c.basic, (const char *)cc.p, cc.len)) return MT_IM_FAILURE;
        mt_dm_changed(at->dm, 0, MT_BASIC_CLUSTER_ID, MT_BASIC_LOCATION);
    }
    if (loc != r->regulatory) {
        if (root_save_regulatory(r, loc)) return MT_IM_FAILURE;
        r->regulatory = loc;
        root_changed(r, MT_GENCOMM_CLUSTER_ID, A_REGULATORY);
    }
    root_set_breadcrumb(r, crumb);
    return respond(resp, resp_cmd, C_SET_REG_RESP, MT_COMM_OK);
}

/* 11.10.7.6. CommissioningComplete is fabric-scoped: without an accessing fabric (PASE before AddNOC) the IM
 * answers UNSUPPORTED_ACCESS (spec 8.8.? / chip CommandHandler). On a PASE session with a fabric, or a CASE session
 * of another fabric than the fail-safe's, the answer is InvalidAuthentication. */
static mt_im_status commissioning_complete(mt_root *r, const mt_im_subject *s, mt_tlv_wr *resp,
                                           uint32_t *resp_cmd)
{
    uint8_t fabric = r->fs.fabric, flags = r->fs.flags;
    if (!s->fabric) return MT_IM_UNSUPPORTED_ACCESS;
    if (!r->fs.armed) return respond(resp, resp_cmd, C_COMPLETE_RESP, MT_COMM_NO_FAILSAFE);
    if (s->auth != MT_IM_AUTH_CASE || fabric != s->fabric)
        return respond(resp, resp_cmd, C_COMPLETE_RESP, MT_COMM_INVALID_AUTH);
    /* The node's commit op first (BLE teardown, before any flash write), then the
     * staged Wi-Fi, then the fabric image. A failure leaves the fail-safe armed with nothing persisted: a failed
     * fabric commit undoes the Wi-Fi one, so the expiry still restores the previous network. */
    if (r->c.ops->commit && r->c.ops->commit(r->c.ctx, fabric)) return MT_IM_FAILURE;
    if (r->stage.commit && r->stage.commit(r->stage.ctx, fabric)) return MT_IM_FAILURE;
    if ((flags & (MT_FS_ADD_NOC | MT_FS_UPDATE_NOC)) && mt_fabric_commit(r->c.fabrics, r->c.scratch)) {
        if (r->stage.undo) r->stage.undo(r->stage.ctx);
        return MT_IM_FAILURE;
    }
    if (r->stage.done) r->stage.done(r->stage.ctx);
    mt_fabric_abort(r->c.fabrics); /* wipes a staged key or root nothing used (e.g. CSR without AddNOC) */
    memset(&r->fs, 0, sizeof r->fs);
    root_set_breadcrumb(r, 0);
    root_changed(r, MT_OPCREDS_CLUSTER_ID, MT_IM_WILD_ID);
    root_event(r, MT_ROOT_EV_COMMISSIONED, fabric, s->session, flags);
    return respond(resp, resp_cmd, C_COMPLETE_RESP, MT_COMM_OK);
}

static mt_im_status gc_invoke(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                              mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_root *r = at->cl->ctx;
    switch (cmd) {
    case C_ARM: return arm_fail_safe(r, s, fields, resp, resp_cmd);
    case C_SET_REG: return set_regulatory(r, at, fields, resp, resp_cmd);
    case C_COMPLETE: return commissioning_complete(r, s, resp, resp_cmd);
    default: return MT_IM_UNSUPPORTED_COMMAND;
    }
}

static const mt_dm_ops ops = { gc_read, gc_write, gc_invoke };

void root_gencomm_init(mt_root *r)
{
    r->gencomm = (mt_dm_cluster){ .id = MT_GENCOMM_CLUSTER_ID, .revision = 1, .n_attrs = MT_DM_N(attrs),
                                  .n_cmds = MT_DM_N(cmds), .n_generated = MT_DM_N(generated), .attrs = attrs,
                                  .cmds = cmds, .generated = generated, .ops = &ops, .ctx = r };
}
