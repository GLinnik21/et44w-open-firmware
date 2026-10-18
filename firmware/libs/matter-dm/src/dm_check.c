/* Table validation: the rules the DM relies on instead of re-checking on every access. */
#include "dm_priv.h"

static mt_err check_cluster(const mt_dm_cluster *cl)
{
    for (unsigned i = 0; i < cl->n_attrs; i++) {
        if (dm_is_global(cl->attrs[i].id)) return MT_ERR_INVALID;
        for (unsigned j = 0; j < i; j++)
            if (cl->attrs[j].id == cl->attrs[i].id) return MT_ERR_INVALID;
    }
    for (unsigned i = 0; i < cl->n_cmds; i++)
        for (unsigned j = 0; j < i; j++)
            if (cl->cmds[j].id == cl->cmds[i].id) return MT_ERR_INVALID;
    return MT_OK;
}

mt_err mt_dm_check(const mt_dm_node *node)
{
    unsigned total = 0;
    if (!node->n_eps || node->eps[0].id != 0) return MT_ERR_INVALID;
    for (unsigned i = 0; i < node->n_eps; i++) {
        const mt_dm_endpoint *ep = &node->eps[i];
        bool desc = false;
        for (unsigned j = 0; j < i; j++)
            if (node->eps[j].id == ep->id) return MT_ERR_INVALID;
        total += ep->n_clusters;
        for (unsigned j = 0; j < ep->n_clusters; j++) {
            const mt_dm_cluster *cl = ep->clusters[j];
            for (unsigned k = 0; k < j; k++)
                if (ep->clusters[k]->id == cl->id) return MT_ERR_INVALID;
            if (cl->id == MT_DM_CLUSTER_DESCRIPTOR) desc = cl == &mt_dm_descriptor;
            mt_err e = check_cluster(cl);
            if (e) return e;
        }
        if (!desc) return MT_ERR_INVALID;
    }
    return total <= MT_DM_MAX_CLUSTERS ? MT_OK : MT_ERR_INVALID;
}
