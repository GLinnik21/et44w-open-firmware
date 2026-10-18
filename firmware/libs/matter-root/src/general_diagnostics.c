/* General Diagnostics cluster (0x33, spec 1.3 section 11.12), see mt_gendiag.h. */
#include "mt_gendiag.h"
#include "root_priv.h"

enum { A_IFACES = 0, A_REBOOTS = 1, A_UPTIME = 2, A_BOOT_REASON = 4, A_TEST_EVENTS = 8 };
enum { C_TEST_EVENT = 0, C_SNAPSHOT = 1, C_SNAPSHOT_RESP = 2 };

#define V MT_IM_PRIV_VIEW

static const mt_dm_attr_def attrs[] = {
    { A_IFACES, MT_IM_ATTR_LIST, V, 0 },
    { A_REBOOTS, 0, V, 0 },
    { A_UPTIME, 0, V, 0 },
    { A_BOOT_REASON, 0, V, 0 },
    { A_TEST_EVENTS, MT_IM_ATTR_FIXED, V, 0 },
};
static const mt_dm_cmd_def cmds[] = { { C_TEST_EVENT, MT_IM_PRIV_MANAGE, false },
                                      { C_SNAPSHOT, MT_IM_PRIV_OPERATE, false } };
static const uint32_t generated[] = { C_SNAPSHOT_RESP };

void mt_gendiag_tick(mt_gendiag *g)
{
    uint32_t now = g->c.now_ms(g->c.ctx);
    g->up_ms += (uint32_t)(now - g->last_ms);
    g->last_ms = now;
}

static bool test_events_enabled(const mt_gendiag *g)
{
    uint8_t any = 0;
    if (!g->c.enable_key || !g->c.trigger) return false;
    for (unsigned i = 0; i < MT_GENDIAG_KEY_LEN; i++) any |= g->c.enable_key[i];
    return any != 0;
}

/* NetworkInterface {0: Name, 1: IsOperational, 2: OffPremiseServicesReachableIPv4 (null), 3: ...IPv6 (null),
 * 4: HardwareAddress, 5: IPv4Addresses, 6: IPv6Addresses, 7: Type} */
static mt_err put_iface(mt_tlv_wr *w, mt_tlv_tag tag, const mt_gendiag_iface *f)
{
    mt_tlv_mark m = mt_tlv_wr_mark(w);
    mt_err e = mt_tlv_start(w, tag, MT_TLV_STRUCT);
    size_t nl = 0;
    while (nl < sizeof f->name - 1 && f->name[nl]) nl++;
    if (!e) e = mt_tlv_put_utf8(w, CTX(0), f->name, nl);
    if (!e) e = mt_tlv_put_bool(w, CTX(1), f->operational);
    if (!e) e = mt_tlv_put_null(w, CTX(2));
    if (!e) e = mt_tlv_put_null(w, CTX(3));
    if (!e) e = mt_tlv_put_bytes(w, CTX(4), mt_span_of(f->hw, f->hw_len));
    if (!e) e = mt_tlv_start(w, CTX(5), MT_TLV_ARRAY);
    for (unsigned i = 0; !e && i < f->n4 && i < MT_GENDIAG_MAX_V4; i++)
        e = mt_tlv_put_bytes(w, mt_tlv_anon(), mt_span_of(f->v4[i], 4));
    if (!e) e = mt_tlv_end(w);
    if (!e) e = mt_tlv_start(w, CTX(6), MT_TLV_ARRAY);
    for (unsigned i = 0; !e && i < f->n6 && i < MT_GENDIAG_MAX_V6; i++)
        e = mt_tlv_put_bytes(w, mt_tlv_anon(), mt_span_of(f->v6[i], 16));
    if (!e) e = mt_tlv_end(w);
    if (!e) e = mt_tlv_put_u(w, CTX(7), f->type);
    if (!e) e = mt_tlv_end(w);
    if (e) mt_tlv_wr_rollback(w, m);
    return e;
}

static mt_err gd_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                      mt_tlv_tag tag)
{
    mt_gendiag *g = at->cl->ctx;
    (void)rc;
    switch (attr) {
    case A_IFACES: {
        mt_gendiag_iface f;
        memset(&f, 0, sizeof f);
        if (item || !g->c.iface || !g->c.iface(g->c.ctx, &f)) return MT_ERR_NOT_FOUND;
        return put_iface(w, tag, &f);
    }
    case A_REBOOTS: return mt_tlv_put_u(w, tag, g->c.reboot_count);
    case A_UPTIME:
        mt_gendiag_tick(g);
        return mt_tlv_put_u(w, tag, g->up_ms / 1000u);
    case A_BOOT_REASON: return mt_tlv_put_u(w, tag, g->c.boot_reason);
    case A_TEST_EVENTS: return mt_tlv_put_bool(w, tag, test_events_enabled(g));
    default: return MT_ERR_NOT_FOUND;
    }
}

/* 11.12.7.1: wrong key (or none configured) is CONSTRAINT_ERROR, a failing trigger INVALID_COMMAND. */
static mt_im_status test_event_trigger(mt_gendiag *g, mt_tlv_rd *f)
{
    mt_tlv_rd x;
    mt_span key;
    uint64_t trigger;
    uint8_t diff = 0;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_bytes(&x, &key) || mt_im_field(f, 1, &x) || mt_tlv_get_u64(&x, &trigger))
        return MT_IM_INVALID_COMMAND;
    if (key.len != MT_GENDIAG_KEY_LEN || !test_events_enabled(g)) return MT_IM_CONSTRAINT_ERROR;
    for (unsigned i = 0; i < MT_GENDIAG_KEY_LEN; i++) diff |= (uint8_t)(key.p[i] ^ g->c.enable_key[i]);
    if (diff) return MT_IM_CONSTRAINT_ERROR;
    return g->c.trigger(g->c.ctx, trigger) ? MT_IM_INVALID_COMMAND : MT_IM_SUCCESS;
}

static mt_im_status gd_invoke(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                              mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_gendiag *g = at->cl->ctx;
    (void)s;
    switch (cmd) {
    case C_TEST_EVENT: return test_event_trigger(g, fields);
    case C_SNAPSHOT: /* {0: SystemTimeMs, 1: PosixTimeMs (null)} */
        mt_gendiag_tick(g);
        if (mt_tlv_put_u(resp, CTX(0), g->up_ms) || mt_tlv_put_null(resp, CTX(1))) return MT_IM_RESOURCE_EXHAUSTED;
        *resp_cmd = C_SNAPSHOT_RESP;
        return MT_IM_SUCCESS;
    default: return MT_IM_UNSUPPORTED_COMMAND;
    }
}

static const mt_dm_ops ops = { gd_read, NULL, gd_invoke };

void mt_gendiag_iface_changed(mt_gendiag *g, mt_dm *dm)
{
    (void)g;
    if (dm) mt_dm_changed(dm, 0, MT_GENDIAG_CLUSTER_ID, A_IFACES);
}

mt_err mt_gendiag_init(mt_gendiag *g, const mt_gendiag_cfg *cfg)
{
    if (!cfg->now_ms) return MT_ERR_INVALID;
    memset(g, 0, sizeof *g);
    g->c = *cfg;
    g->last_ms = cfg->now_ms(cfg->ctx);
    g->cluster = (mt_dm_cluster){ .id = MT_GENDIAG_CLUSTER_ID, .revision = 2, .n_attrs = MT_DM_N(attrs),
                                  .n_cmds = MT_DM_N(cmds), .n_generated = MT_DM_N(generated), .attrs = attrs,
                                  .cmds = cmds, .generated = generated, .ops = &ops, .ctx = g };
    return MT_OK;
}
