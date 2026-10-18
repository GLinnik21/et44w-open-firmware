/* Access Control cluster (0x1F, spec 1.3 section 9.10) and the access check of section 6.6.6, see mt_root_comm.h.
 * Write rules as in connectedhomeip v1.3 access-control-server.cpp, check as in access/AccessControl.cpp. */
#include "root_priv.h"

enum { A_ACL = 0, A_SUBJECTS_PER = 2, A_TARGETS_PER = 3, A_ENTRIES_PER = 4 };

#define V MT_IM_PRIV_VIEW
#define ADM MT_IM_PRIV_ADMINISTER
#define FX MT_IM_ATTR_FIXED

static const mt_dm_attr_def attrs[] = {
    { A_ACL, MT_IM_ATTR_LIST | MT_IM_ATTR_WRITABLE, ADM, ADM },
    { A_SUBJECTS_PER, FX, V, 0 },
    { A_TARGETS_PER, FX, V, 0 },
    { A_ENTRIES_PER, FX, V, 0 },
};

/* ---- the check (6.6.6) ---- */

/* Does an entry with privilege `granted` cover a request for `req`? (6.6.2.1: Administer covers all, Manage covers
 * Operate and View, Operate covers View, ProxyView covers View; nothing but Administer covers ProxyView.) */
static bool priv_covers(uint8_t granted, uint8_t req)
{
    switch (req) {
    case MT_IM_PRIV_VIEW: return granted >= MT_IM_PRIV_VIEW && granted <= MT_IM_PRIV_ADMINISTER;
    case MT_IM_PRIV_PROXY_VIEW: return granted == MT_IM_PRIV_PROXY_VIEW || granted == MT_IM_PRIV_ADMINISTER;
    case MT_IM_PRIV_OPERATE:
    case MT_IM_PRIV_MANAGE:
    case MT_IM_PRIV_ADMINISTER: return granted >= req && granted <= MT_IM_PRIV_ADMINISTER;
    default: return false;
    }
}

/* Subject match (6.6.2.2): operational node ID equal, or a CAT (0xFFFFFFFD_IIIIVVVV) whose identifier the session
 * holds with a version >= the entry's. */
static bool subject_matches(uint64_t subj, const mt_root_session *s)
{
    if ((subj >> 32) == 0xFFFFFFFDu) {
        for (unsigned i = 0; i < s->n_cats && i < MT_CERT_MAX_CATS; i++)
            if ((s->cats[i] >> 16) == ((uint32_t)subj >> 16) && (s->cats[i] & 0xFFFFu) >= (subj & 0xFFFFu))
                return true;
        return false;
    }
    return subj >= 1 && subj <= MT_CERT_NODE_ID_MAX && subj == s->peer_node;
}

static bool devtype_on(const mt_dm_node *node, uint16_t endpoint, uint32_t type)
{
    for (unsigned i = 0; node && i < node->n_eps; i++) {
        const mt_dm_endpoint *ep = &node->eps[i];
        if (ep->id != endpoint) continue;
        for (unsigned k = 0; k < ep->n_types; k++)
            if (ep->types[k].type == type) return true;
    }
    return false;
}

static bool target_matches(const mt_acl_target *t, const mt_dm_node *node, uint16_t endpoint, uint32_t cluster)
{
    if (t->cluster != MT_ACL_NO_CLUSTER && t->cluster != cluster) return false;
    if (t->endpoint != MT_ACL_NO_ENDPOINT && t->endpoint != endpoint) return false;
    if (t->devtype != MT_ACL_NO_DEVTYPE && !devtype_on(node, endpoint, t->devtype)) return false;
    return true;
}

static bool entry_grants(const mt_acl_entry *e, const mt_dm_node *node, const mt_root_session *s, uint16_t endpoint,
                         uint32_t cluster, uint8_t priv)
{
    bool hit = e->n_subjects == 0;
    if (e->auth_mode != MT_ACL_AUTH_CASE || !priv_covers(e->privilege, priv)) return false;
    for (unsigned i = 0; !hit && i < e->n_subjects; i++) hit = subject_matches(e->subjects[i], s);
    if (!hit) return false;
    hit = e->n_targets == 0;
    for (unsigned i = 0; !hit && i < e->n_targets; i++) hit = target_matches(&e->targets[i], node, endpoint, cluster);
    return hit;
}

bool mt_acl_check(const mt_fabric_table *t, const mt_dm_node *node, const mt_root_session *s, uint16_t endpoint,
                  uint32_t cluster, uint8_t priv)
{
    const mt_fabric *f;
    if (s->auth == MT_IM_AUTH_PASE) return true; /* PASE is the commissioning channel: implicit Administer */
    if (s->auth != MT_IM_AUTH_CASE || !(f = mt_fabric_get(t, s->fabric))) return false;
    for (unsigned i = 0; i < f->n_acl; i++)
        if (entry_grants(&f->acl[i], node, s, endpoint, cluster, priv)) return true;
    return false;
}

bool mt_root_access(void *ctx, const mt_im_subject *s, uint16_t endpoint, uint32_t cluster, uint8_t priv)
{
    mt_root *r = ctx;
    mt_root_session ss;
    if (s->auth == MT_IM_AUTH_PASE) return true;
    if (!root_session(r, s->session, &ss)) memset(&ss, 0, sizeof ss); /* no CATs known */
    ss.auth = s->auth; /* the IM's view of the subject is authoritative */
    ss.fabric = s->fabric;
    ss.peer_node = s->node;
    return mt_acl_check(r->c.fabrics, r->dm ? r->dm->node : NULL, &ss, endpoint, cluster, priv);
}

/* ---- the cluster ---- */

/* ACL list item `item` across fabrics (fabric filtering, 8.4.3.2). Other fabrics' entries show only the index:
 * every field of AccessControlEntryStruct is fabric-sensitive (9.10.4.5). */
static mt_err acl_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                       mt_tlv_tag tag)
{
    const mt_root *r = at->cl->ctx;
    const mt_fabric *f;
    unsigned k = 0;
    switch (attr) {
    case A_SUBJECTS_PER: return mt_tlv_put_u(w, tag, MT_ACL_MAX_SUBJECTS);
    case A_TARGETS_PER: return mt_tlv_put_u(w, tag, MT_ACL_MAX_TARGETS);
    case A_ENTRIES_PER: return mt_tlv_put_u(w, tag, MT_ACL_MAX_ENTRIES);
    case A_ACL: break;
    default: return MT_ERR_NOT_FOUND;
    }
    for (unsigned n = 0; (f = mt_fabric_nth(r->c.fabrics, n)) != NULL; n++) {
        if (rc->fabric_filtered && f->index != rc->subj->fabric) continue;
        if (item >= k + f->n_acl) { k += f->n_acl; continue; }
        mt_tlv_mark m = mt_tlv_wr_mark(w);
        mt_err e = mt_tlv_start(w, tag, MT_TLV_STRUCT);
        if (!e && f->index == rc->subj->fabric) e = mt_acl_entry_encode_fields(w, &f->acl[item - k]);
        if (!e) e = mt_tlv_put_u(w, CTX(TAG_FABRIC_INDEX), f->index);
        if (!e) e = mt_tlv_end(w);
        if (e) mt_tlv_wr_rollback(w, m);
        return e;
    }
    return MT_ERR_NOT_FOUND;
}

/* One written entry: decoded (the fabric index field is ignored, the accessing fabric owns it) and validated. */
static mt_im_status decode_entry(mt_tlv_rd *v, mt_acl_entry *e)
{
    mt_err err = mt_acl_entry_decode(v, e);
    if (err == MT_ERR_BUFFER_TOO_SMALL) return MT_IM_RESOURCE_EXHAUSTED; /* more subjects/targets than supported */
    if (err) return MT_IM_CONSTRAINT_ERROR;
    return mt_acl_entry_valid(e) ? MT_IM_SUCCESS : MT_IM_CONSTRAINT_ERROR;
}

/* 9.10.5.3: replace the accessing fabric's entries (list write) or append one. Persisted at once. */
static mt_im_status acl_write(const mt_dm_at *at, const mt_im_wctx *wc, uint32_t attr, mt_im_wr_op op, mt_tlv_rd *val)
{
    mt_root *r = at->cl->ctx;
    mt_acl_entry list[MT_ACL_MAX_ENTRIES];
    unsigned n = 0;
    uint8_t fabric = wc->subj->fabric;
    const mt_fabric *f;
    mt_im_status st = MT_IM_SUCCESS;
    mt_err e = MT_OK;
    if (attr != A_ACL) return MT_IM_UNSUPPORTED_WRITE;
    if (!fabric || !(f = mt_fabric_get(r->c.fabrics, fabric))) return MT_IM_UNSUPPORTED_ACCESS; /* fabric-scoped */
    if (op == MT_IM_WR_LIST_APPEND) {
        mt_acl_entry add;
        if ((st = decode_entry(val, &add)) != MT_IM_SUCCESS) return st;
        if (f->n_acl >= MT_ACL_MAX_ENTRIES) return MT_IM_RESOURCE_EXHAUSTED;
        for (n = 0; n < f->n_acl; n++) list[n] = f->acl[n];
        list[n++] = add;
    } else {
        mt_tlv_rd it = *val;
        if (it.type != MT_TLV_ARRAY || mt_tlv_enter(&it)) return MT_IM_INVALID_DATA_TYPE;
        while (!st && !(e = mt_tlv_next(&it))) {
            if (n == MT_ACL_MAX_ENTRIES) return MT_IM_RESOURCE_EXHAUSTED;
            st = decode_entry(&it, &list[n++]);
        }
        if (st) return st;
        if (e != MT_ERR_NOT_FOUND) return MT_IM_INVALID_DATA_TYPE;
    }
    if (mt_fabric_acl_set(r->c.fabrics, fabric, list, n, r->c.scratch)) return MT_IM_FAILURE;
    return MT_IM_SUCCESS;
}

static const mt_dm_ops ops = { acl_read, acl_write, NULL };

void root_acl_init(mt_root *r)
{
    r->acl = (mt_dm_cluster){ .id = MT_ACL_CLUSTER_ID, .revision = 1, .n_attrs = MT_DM_N(attrs), .attrs = attrs,
                              .ops = &ops, .ctx = r };
}
