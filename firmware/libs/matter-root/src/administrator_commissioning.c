/* Administrator Commissioning cluster (0x3C, spec 1.3 section 11.19), see mt_admincomm.h. */
#include "mt_admincomm.h"
#include "root_priv.h"

enum { A_STATUS = 0, A_FABRIC = 1, A_VENDOR = 2 };
enum { C_OPEN = 0, C_REVOKE = 2 };

#define V MT_IM_PRIV_VIEW
#define ADM MT_IM_PRIV_ADMINISTER

static const mt_dm_attr_def attrs[] = { { A_STATUS, 0, V, 0 }, { A_FABRIC, 0, V, 0 }, { A_VENDOR, 0, V, 0 } };
static const mt_dm_cmd_def cmds[] = { { C_OPEN, ADM, true }, { C_REVOKE, ADM, true } };

static void changed(mt_admin *a) { root_changed(a->c.root, MT_ADMIN_CLUSTER_ID, MT_IM_WILD_ID); }

static mt_err ad_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                      mt_tlv_tag tag)
{
    mt_admin *a = at->cl->ctx;
    uint8_t st = a->c.ops->status(a->c.ctx);
    (void)rc; (void)item;
    switch (attr) {
    /* 11.19.7.1: only a window an Administrator opened through this cluster shows here; the boot window reads
     * WindowNotOpen (chip v1.3 CommissioningWindowManager::CommissioningWindowStatusForCluster). */
    case A_STATUS: return mt_tlv_put_u(w, tag, a->fabric ? st : MT_WINDOW_NOT_OPEN);
    case A_FABRIC: return st == MT_WINDOW_NOT_OPEN || !a->fabric ? mt_tlv_put_null(w, tag) : mt_tlv_put_u(w, tag, a->fabric);
    case A_VENDOR: return st == MT_WINDOW_NOT_OPEN || !a->fabric ? mt_tlv_put_null(w, tag) : mt_tlv_put_u(w, tag, a->vendor_id);
    default: return MT_ERR_NOT_FOUND;
    }
}

/* 11.19.8.1. Order of checks as chip: fabric, fail-safe, open window, PBKDF parameters (cluster statuses), then
 * timeout and discriminator (INVALID_COMMAND), then the verifier. */
static mt_im_status open_window(mt_admin *a, const mt_im_subject *s, mt_tlv_rd *f)
{
    mt_tlv_rd x;
    mt_admin_window w;
    mt_span verifier, salt;
    const mt_fabric *fab;
    memset(&w, 0, sizeof w);
    if (mt_im_field(f, 0, &x) || mt_tlv_get_u16(&x, &w.timeout_s) || mt_im_field(f, 1, &x) ||
        mt_tlv_get_bytes(&x, &verifier) || mt_im_field(f, 2, &x) || mt_tlv_get_u16(&x, &w.discriminator) ||
        mt_im_field(f, 3, &x) || mt_tlv_get_u32(&x, &w.iterations) || mt_im_field(f, 4, &x) ||
        mt_tlv_get_bytes(&x, &salt))
        return MT_IM_INVALID_COMMAND;
    fab = s->fabric ? mt_fabric_get(a->c.root->c.fabrics, s->fabric) : NULL;
    if (!fab) return MT_IM_CST(MT_ADMIN_PAKE_PARAMETER_ERROR);
    if (a->c.root->fs.armed || a->c.ops->status(a->c.ctx) != MT_WINDOW_NOT_OPEN) return MT_IM_CST(MT_ADMIN_BUSY);
    if (w.iterations < MT_ADMIN_ITERATIONS_MIN || w.iterations > MT_ADMIN_ITERATIONS_MAX ||
        salt.len < MT_ADMIN_SALT_MIN || salt.len > MT_ADMIN_SALT_MAX)
        return MT_IM_CST(MT_ADMIN_PAKE_PARAMETER_ERROR);
    if (w.timeout_s < MT_ADMIN_TIMEOUT_MIN_S || w.timeout_s > MT_ADMIN_TIMEOUT_MAX_S ||
        w.discriminator > MT_ADMIN_MAX_DISCRIMINATOR)
        return MT_IM_INVALID_COMMAND;
    if (verifier.len != MT_ADMIN_VERIFIER_LEN) return MT_IM_CST(MT_ADMIN_PAKE_PARAMETER_ERROR);
    memcpy(w.w0, verifier.p, sizeof w.w0);
    memcpy(w.l, verifier.p + sizeof w.w0, sizeof w.l);
    w.salt = salt;
    w.fabric = fab->index;
    w.vendor_id = fab->vendor_id;
    if (a->c.ops->open(a->c.ctx, &w)) {
        mt_wipe(&w, sizeof w);
        return MT_IM_CST(MT_ADMIN_PAKE_PARAMETER_ERROR);
    }
    mt_wipe(&w.w0, sizeof w.w0);
    a->fabric = fab->index;
    a->vendor_id = fab->vendor_id;
    changed(a);
    return MT_IM_SUCCESS;
}

/* 11.19.8.3. Like chip, any armed fail-safe is ended first. */
static mt_im_status revoke(mt_admin *a)
{
    mt_root_failsafe_expire(a->c.root);
    if (a->c.ops->status(a->c.ctx) == MT_WINDOW_NOT_OPEN) return MT_IM_CST(MT_ADMIN_WINDOW_NOT_OPEN);
    a->c.ops->close(a->c.ctx);
    a->fabric = 0;
    changed(a);
    return MT_IM_SUCCESS;
}

static mt_im_status ad_invoke(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                              mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_admin *a = at->cl->ctx;
    (void)resp; (void)resp_cmd;
    switch (cmd) {
    case C_OPEN: return open_window(a, s, fields);
    case C_REVOKE: return revoke(a);
    default: return MT_IM_UNSUPPORTED_COMMAND;
    }
}

static const mt_dm_ops ops = { ad_read, NULL, ad_invoke };

void mt_admin_window_changed(mt_admin *a)
{
    if (a->c.ops->status(a->c.ctx) == MT_WINDOW_NOT_OPEN) a->fabric = 0;
    changed(a);
}

void mt_admin_fabric_removed(mt_admin *a, uint8_t fabric)
{
    if (!fabric || a->fabric != fabric) return;
    if (a->c.ops->status(a->c.ctx) != MT_WINDOW_NOT_OPEN) a->c.ops->close(a->c.ctx);
    a->fabric = 0;
    changed(a);
}

mt_err mt_admin_init(mt_admin *a, const mt_admin_cfg *cfg)
{
    if (!cfg->ops || !cfg->ops->status || !cfg->ops->open || !cfg->ops->close || !cfg->root) return MT_ERR_INVALID;
    memset(a, 0, sizeof *a);
    a->c = *cfg;
    a->cluster = (mt_dm_cluster){ .id = MT_ADMIN_CLUSTER_ID, .revision = 1, .n_attrs = MT_DM_N(attrs),
                                  .n_cmds = MT_DM_N(cmds), .attrs = attrs, .cmds = cmds, .ops = &ops, .ctx = a };
    return MT_OK;
}
