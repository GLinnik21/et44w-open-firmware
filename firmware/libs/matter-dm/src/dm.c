/* The mt_im_dm implementation: attribute enumeration, global attributes, dispatch, data versions. */
#include "dm_priv.h"


/* ---- table walking ---- */

bool dm_locate(const mt_dm_node *node, uint16_t endpoint, uint32_t cluster, dm_loc *out)
{
    uint8_t cidx = 0;
    for (uint8_t i = 0; i < node->n_eps; i++) {
        const mt_dm_endpoint *ep = &node->eps[i];
        if (ep->id != endpoint) {
            cidx = (uint8_t)(cidx + ep->n_clusters);
            continue;
        }
        for (uint8_t j = 0; j < ep->n_clusters; j++)
            if (ep->clusters[j]->id == cluster) {
                out->ep = ep;
                out->cl = ep->clusters[j];
                out->cidx = (uint8_t)(cidx + j);
                return true;
            }
        return false;
    }
    return false;
}

static unsigned n_globals(const mt_dm_cluster *cl) { return cl->n_events ? 6u : 5u; }

/* Number of attributes of a cluster as listed in AttributeList and enumerated by attr_at. */
static uint16_t attr_count(const mt_dm_cluster *cl) { return (uint16_t)(cl->n_attrs + n_globals(cl)); }

static uint32_t global_id(const mt_dm_cluster *cl, unsigned k)
{
    return DM_GLOBAL_FIRST + k + (!cl->n_events && k >= 2 ? 1u : 0u);   /* 0xFFFA only with events */
}

/* The k-th attribute of a cluster: its own, then the globals. */
static void attr_desc(const mt_dm_cluster *cl, unsigned k, mt_dm_attr_def *d)
{
    if (k < cl->n_attrs) {
        *d = cl->attrs[k];
        return;
    }
    d->id = global_id(cl, k - cl->n_attrs);
    d->read_priv = MT_IM_PRIV_VIEW;
    d->write_priv = 0;
    d->flags = MT_IM_ATTR_FIXED;
    if (d->id <= MT_DM_ATTR_ATTR_LIST) d->flags |= MT_IM_ATTR_LIST;
}

static mt_err attr_at(void *ctx, uint16_t idx, mt_im_attr *out)
{
    const mt_dm *dm = ctx;
    uint8_t cidx = 0;
    for (uint8_t i = 0; i < dm->node->n_eps; i++) {
        const mt_dm_endpoint *ep = &dm->node->eps[i];
        for (uint8_t j = 0; j < ep->n_clusters; j++, cidx++) {
            const mt_dm_cluster *cl = ep->clusters[j];
            uint16_t n = attr_count(cl);
            if (idx >= n) {
                idx = (uint16_t)(idx - n);
                continue;
            }
            mt_dm_attr_def d;
            attr_desc(cl, idx, &d);
            out->endpoint = ep->id;
            out->cluster = cl->id;
            out->attr = d.id;
            out->dataver = dm->dataver[cidx];
            out->flags = d.write_priv ? d.flags : (uint8_t)(d.flags & ~MT_IM_ATTR_WRITABLE); /* write_priv 0 = read-only */
            out->read_priv = d.read_priv;
            out->write_priv = d.write_priv;
            out->cluster_idx = cidx;
            return MT_OK;
        }
    }
    return MT_ERR_NOT_FOUND;
}

/* ---- read ---- */

static mt_err put_id(mt_tlv_wr *w, mt_tlv_tag tag, uint16_t item, unsigned n, uint32_t id)
{
    return item < n ? mt_tlv_put_u(w, tag, id) : MT_ERR_NOT_FOUND;
}

static mt_err read_global(const mt_dm_cluster *cl, uint32_t attr, uint16_t item, mt_tlv_wr *w, mt_tlv_tag tag)
{
    mt_dm_attr_def d = { 0, 0, 0, 0 };
    switch (attr) {
    case MT_DM_ATTR_CLUSTER_REV: return mt_tlv_put_u(w, tag, cl->revision);
    case MT_DM_ATTR_FEATURE_MAP: return mt_tlv_put_u(w, tag, cl->features);
    case MT_DM_ATTR_ATTR_LIST:
        if (item < attr_count(cl)) attr_desc(cl, item, &d);
        return put_id(w, tag, item, attr_count(cl), d.id);
    case MT_DM_ATTR_ACCEPTED_CMDS:
        return put_id(w, tag, item, cl->n_cmds, item < cl->n_cmds ? cl->cmds[item].id : 0);
    case MT_DM_ATTR_GENERATED_CMDS:
        return put_id(w, tag, item, cl->n_generated, item < cl->n_generated ? cl->generated[item] : 0);
    case MT_DM_ATTR_EVENT_LIST:
        return put_id(w, tag, item, cl->n_events, item < cl->n_events ? cl->events[item] : 0);
    default: return MT_ERR_INVALID;
    }
}

static void make_at(mt_dm *dm, const dm_loc *l, mt_dm_at *at)
{
    at->dm = dm;
    at->ep = l->ep;
    at->cl = l->cl;
}

static mt_err dm_read(void *ctx, const mt_im_rctx *rc, const mt_im_attr *a, uint16_t item, mt_tlv_wr *w,
                      mt_tlv_tag tag)
{
    mt_dm *dm = ctx;
    dm_loc l;
    if (!dm_locate(dm->node, a->endpoint, a->cluster, &l)) return MT_ERR_INVALID;
    if (dm_is_global(a->attr)) return read_global(l.cl, a->attr, item, w, tag);
    if (!l.cl->ops || !l.cl->ops->read) return MT_ERR_UNSUPPORTED;
    mt_dm_at at;
    make_at(dm, &l, &at);
    return l.cl->ops->read(&at, rc, a->attr, item, w, tag);
}

/* ---- write, invoke ---- */

static mt_im_status dm_write(void *ctx, const mt_im_wctx *wc, const mt_im_attr *a, mt_im_wr_op op, mt_tlv_rd *val)
{
    mt_dm *dm = ctx;
    dm_loc l;
    if (!(a->flags & MT_IM_ATTR_WRITABLE) || !a->write_priv || !dm_locate(dm->node, a->endpoint, a->cluster, &l) ||
        dm_is_global(a->attr) || !l.cl->ops || !l.cl->ops->write)
        return MT_IM_UNSUPPORTED_WRITE;
    mt_dm_at at;
    make_at(dm, &l, &at);
    mt_im_status st = l.cl->ops->write(&at, wc, a->attr, op, val);
    if (st == MT_IM_SUCCESS) mt_dm_changed(dm, a->endpoint, a->cluster, a->attr);
    return st;
}

static mt_err dm_cmd_info(void *ctx, const mt_im_cmd *c, uint8_t *priv, bool *timed)
{
    const mt_dm *dm = ctx;
    dm_loc l;
    if (!dm_locate(dm->node, c->endpoint, c->cluster, &l)) return MT_ERR_NOT_FOUND;
    for (uint8_t i = 0; i < l.cl->n_cmds; i++)
        if (l.cl->cmds[i].id == c->command) {
            *priv = l.cl->cmds[i].priv;
            *timed = l.cl->cmds[i].timed;
            return MT_OK;
        }
    return MT_ERR_NOT_FOUND;
}

static mt_im_status dm_invoke(void *ctx, const mt_im_subject *s, const mt_im_cmd *c, mt_tlv_rd *fields,
                              mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_dm *dm = ctx;
    dm_loc l;
    if (!dm_locate(dm->node, c->endpoint, c->cluster, &l) || !l.cl->ops || !l.cl->ops->invoke)
        return MT_IM_UNSUPPORTED_COMMAND;
    mt_dm_at at;
    make_at(dm, &l, &at);
    return l.cl->ops->invoke(&at, s, c->command, fields, resp, resp_cmd);
}

static bool dm_access(void *ctx, const mt_im_subject *s, uint16_t endpoint, uint32_t cluster, uint8_t priv)
{
    const mt_dm *dm = ctx;
    return dm->access && dm->access(dm->access_ctx, s, endpoint, cluster, priv);
}

const mt_im_dm mt_dm_im = { attr_at, dm_read, dm_write, dm_cmd_info, dm_invoke, dm_access };

/* ---- instance ---- */

mt_err mt_dm_init(mt_dm *dm, const mt_dm_cfg *cfg)
{
    mt_err e = mt_dm_check(cfg->node);
    if (e) return e;
    dm->node = cfg->node;
    dm->im = cfg->im;
    dm->access = cfg->access;
    dm->access_ctx = cfg->access_ctx;
    for (unsigned i = 0; i < MT_DM_MAX_CLUSTERS; i++) dm->dataver[i] = cfg->dataver_seed + i;
    return MT_OK;
}

void mt_dm_changed(mt_dm *dm, uint16_t endpoint, uint32_t cluster, uint32_t attr)
{
    dm_loc l;
    if (!dm_locate(dm->node, endpoint, cluster, &l)) return;
    dm->dataver[l.cidx]++;
    if (dm->im) mt_im_mark_dirty(dm->im, endpoint, cluster, attr);
}

bool mt_dm_dataver(const mt_dm *dm, uint16_t endpoint, uint32_t cluster, uint32_t *out)
{
    dm_loc l;
    if (!dm_locate(dm->node, endpoint, cluster, &l)) return false;
    *out = dm->dataver[l.cidx];
    return true;
}
