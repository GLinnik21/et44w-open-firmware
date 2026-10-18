/* Group Key Management cluster (0x3F, spec 1.3 section 11.2), see mt_root_comm.h. Only key set 0, the IPK that
 * AddNOC installs with the fabric (epoch start time 0, TrustFirst, as chip v1.3 AddNOC stores it); no groups.
 * Command rules as in connectedhomeip v1.3 group-key-mgmt-server.cpp. */
#include "root_priv.h"

enum { A_KEY_MAP = 0, A_GROUP_TABLE = 1, A_MAX_GROUPS = 2, A_MAX_KEYS = 3 };
enum { C_WRITE = 0, C_READ = 1, C_READ_RESP = 2, C_REMOVE = 3, C_READ_ALL = 4, C_READ_ALL_RESP = 5 };
enum { IPK_KEYSET = 0, POLICY_TRUST_FIRST = 0 };

#define V MT_IM_PRIV_VIEW
#define ADM MT_IM_PRIV_ADMINISTER
#define FX MT_IM_ATTR_FIXED

static const mt_dm_attr_def attrs[] = {
    { A_KEY_MAP, MT_IM_ATTR_LIST | MT_IM_ATTR_WRITABLE, V, MT_IM_PRIV_MANAGE },
    { A_GROUP_TABLE, MT_IM_ATTR_LIST, V, 0 },
    { A_MAX_GROUPS, FX, V, 0 },
    { A_MAX_KEYS, FX, V, 0 },
};
static const mt_dm_cmd_def cmds[] = { { C_WRITE, ADM, false }, { C_READ, ADM, false }, { C_REMOVE, ADM, false },
                                      { C_READ_ALL, ADM, false } };
static const uint32_t generated[] = { C_READ_RESP, C_READ_ALL_RESP };

static mt_err gkm_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                       mt_tlv_tag tag)
{
    (void)at; (void)rc; (void)item;
    switch (attr) {
    case A_MAX_GROUPS: return mt_tlv_put_u(w, tag, MT_ROOT_MAX_GROUPS_PER_FABRIC);
    case A_MAX_KEYS: return mt_tlv_put_u(w, tag, MT_ROOT_MAX_GROUP_KEYS_PER_FABRIC);
    default: return MT_ERR_NOT_FOUND; /* GroupKeyMap and GroupTable are empty lists */
    }
}

/* GroupKeyMapStruct {1: GroupId, 2: GroupKeySetID}. Mapping to the IPK is a constraint error (11.2.6.3);
 * any other mapping needs a group, and MaxGroupsPerFabric is 0. */
static mt_im_status map_entry(mt_tlv_rd *v)
{
    mt_tlv_rd x = *v;
    uint16_t keyset;
    if (x.type != MT_TLV_STRUCT || mt_tlv_enter(&x) || mt_tlv_find_ctx(&x, 2) || mt_tlv_get_u16(&x, &keyset))
        return MT_IM_INVALID_DATA_TYPE;
    return keyset == IPK_KEYSET ? MT_IM_CONSTRAINT_ERROR : MT_IM_RESOURCE_EXHAUSTED;
}

static mt_im_status gkm_write(const mt_dm_at *at, const mt_im_wctx *wc, uint32_t attr, mt_im_wr_op op, mt_tlv_rd *val)
{
    mt_tlv_rd it;
    mt_err e;
    (void)at;
    if (attr != A_KEY_MAP) return MT_IM_UNSUPPORTED_WRITE;
    if (!wc->subj->fabric) return MT_IM_UNSUPPORTED_ACCESS; /* fabric-scoped */
    if (op == MT_IM_WR_LIST_APPEND) return map_entry(val);
    it = *val;
    if (it.type != MT_TLV_ARRAY || mt_tlv_enter(&it)) return MT_IM_INVALID_DATA_TYPE;
    if (!(e = mt_tlv_next(&it))) return map_entry(&it);
    return e == MT_ERR_NOT_FOUND ? MT_IM_SUCCESS : MT_IM_INVALID_DATA_TYPE; /* empty list: nothing to store */
}

/* 11.2.7.1. Only the structure is checked before refusing: the IPK is not rotated through this command here
 * (chip would overwrite it) and there is no room for another key set (RESOURCE_EXHAUSTED as chip on a full table). */
static mt_im_status key_set_write(mt_tlv_rd *f)
{
    mt_tlv_rd x;
    uint16_t id;
    mt_span key;
    if (mt_im_field(f, 0, &x) || x.type != MT_TLV_STRUCT) return MT_IM_INVALID_COMMAND;
    {
        mt_tlv_rd s = x, k = x;
        if (mt_tlv_enter(&s) || mt_tlv_find_ctx(&s, 0) || mt_tlv_get_u16(&s, &id)) return MT_IM_INVALID_COMMAND;
        if (mt_tlv_enter(&k) || mt_tlv_find_ctx(&k, 2) || k.type == MT_TLV_NULL) return MT_IM_INVALID_COMMAND;
        if (mt_tlv_get_bytes(&k, &key)) return MT_IM_INVALID_COMMAND;
        if (key.len != MT_IPK_LEN) return MT_IM_CONSTRAINT_ERROR;
    }
    return id == IPK_KEYSET ? MT_IM_INVALID_COMMAND : MT_IM_RESOURCE_EXHAUSTED;
}

/* 11.2.7.2: KeySetReadResponse {0: GroupKeySetStruct} with every epoch key null. */
static mt_im_status key_set_read(mt_tlv_rd *f, mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_tlv_rd x;
    uint16_t id;
    mt_err e;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_u16(&x, &id)) return MT_IM_INVALID_COMMAND;
    if (id != IPK_KEYSET) return MT_IM_NOT_FOUND;
    e = mt_tlv_start(resp, CTX(0), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_u(resp, CTX(0), IPK_KEYSET);
    if (!e) e = mt_tlv_put_u(resp, CTX(1), POLICY_TRUST_FIRST);
    if (!e) e = mt_tlv_put_null(resp, CTX(2));
    if (!e) e = mt_tlv_put_u(resp, CTX(3), 0); /* EpochStartTime0 */
    for (uint8_t t = 4; !e && t <= 7; t++) e = mt_tlv_put_null(resp, CTX(t));
    if (!e) e = mt_tlv_end(resp);
    if (e) return MT_IM_RESOURCE_EXHAUSTED;
    *resp_cmd = C_READ_RESP;
    return MT_IM_SUCCESS;
}

static mt_im_status gkm_invoke(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                               mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    const mt_root *r = at->cl->ctx;
    mt_tlv_rd x;
    uint16_t id;
    if (!s->fabric) return MT_IM_UNSUPPORTED_ACCESS; /* all four commands are fabric-scoped */
    if (!mt_fabric_get(r->c.fabrics, s->fabric)) return MT_IM_FAILURE;
    switch (cmd) {
    case C_WRITE: return key_set_write(fields);
    case C_READ: return key_set_read(fields, resp, resp_cmd);
    case C_REMOVE: /* 11.2.7.4 */
        if (mt_im_field(fields, 0, &x) || mt_tlv_get_u16(&x, &id)) return MT_IM_INVALID_COMMAND;
        return id == IPK_KEYSET ? MT_IM_INVALID_COMMAND : MT_IM_NOT_FOUND;
    case C_READ_ALL: /* 11.2.7.5: {0: [GroupKeySetID]} */
        if (mt_tlv_start(resp, CTX(0), MT_TLV_ARRAY) || mt_tlv_put_u(resp, mt_tlv_anon(), IPK_KEYSET) || mt_tlv_end(resp))
            return MT_IM_RESOURCE_EXHAUSTED;
        *resp_cmd = C_READ_ALL_RESP;
        return MT_IM_SUCCESS;
    default: return MT_IM_UNSUPPORTED_COMMAND;
    }
}

static const mt_dm_ops ops = { gkm_read, gkm_write, gkm_invoke };

void root_gkm_init(mt_root *r)
{
    r->gkm = (mt_dm_cluster){ .id = MT_GKM_CLUSTER_ID, .revision = 2, .n_attrs = MT_DM_N(attrs),
                              .n_cmds = MT_DM_N(cmds), .n_generated = MT_DM_N(generated), .attrs = attrs,
                              .cmds = cmds, .generated = generated, .ops = &ops, .ctx = r };
}
