/* Descriptor cluster (0x1D, spec 9.5): what an endpoint is and which clusters and parts it has.
 * Derived entirely from the endpoint table, so it never disagrees with the rest of the node.
 * PartsList is flat: endpoint 0 lists every other endpoint, all others list none. */
#include "dm_priv.h"

enum { ATTR_DEVTYPES = 0, ATTR_SERVERS = 1, ATTR_CLIENTS = 2, ATTR_PARTS = 3 };

static mt_err desc_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                        mt_tlv_tag tag)
{
    (void)rc;
    const mt_dm_endpoint *ep = at->ep;
    switch (attr) {
    case ATTR_DEVTYPES: {
        if (item >= ep->n_types) return MT_ERR_NOT_FOUND;
        mt_err e = mt_tlv_start(w, tag, MT_TLV_STRUCT);
        if (!e) e = mt_tlv_put_u(w, mt_tlv_ctx(0), ep->types[item].type);
        if (!e) e = mt_tlv_put_u(w, mt_tlv_ctx(1), ep->types[item].revision);
        return e ? e : mt_tlv_end(w);
    }
    case ATTR_SERVERS:
        return item < ep->n_clusters ? mt_tlv_put_u(w, tag, ep->clusters[item]->id) : MT_ERR_NOT_FOUND;
    case ATTR_CLIENTS:
        return item < ep->n_clients ? mt_tlv_put_u(w, tag, ep->clients[item]) : MT_ERR_NOT_FOUND;
    case ATTR_PARTS:
        return ep->id == 0 && item + 1u < at->dm->node->n_eps ? mt_tlv_put_u(w, tag, at->dm->node->eps[item + 1u].id)
                                                               : MT_ERR_NOT_FOUND;
    default: return MT_ERR_INVALID;
    }
}

static const mt_dm_ops k_ops = { desc_read, 0, 0 };

#define L MT_IM_ATTR_LIST
#define F MT_IM_ATTR_FIXED
#define V MT_IM_PRIV_VIEW
static const mt_dm_attr_def k_attrs[] = {
    { ATTR_DEVTYPES, L | F, V, 0 }, { ATTR_SERVERS, L | F, V, 0 },
    { ATTR_CLIENTS, L | F, V, 0 },  { ATTR_PARTS, L, V, 0 },
};

const mt_dm_cluster mt_dm_descriptor = {
    .id = MT_DM_CLUSTER_DESCRIPTOR, .revision = 2, .attrs = k_attrs,
    .n_attrs = MT_DM_N(k_attrs), .ops = &k_ops,
};
