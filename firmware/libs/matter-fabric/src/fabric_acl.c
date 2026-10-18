#include "fabric_internal.h"

static bool subject_ok(uint8_t auth, uint64_t s)
{
    if (auth == MT_ACL_AUTH_CASE) {
        if (s >= 1 && s <= MT_CERT_NODE_ID_MAX) return true;
        return (s >> 32) == 0xFFFFFFFDu && (s & 0xFFFFu) != 0;      /* CAT with a non-zero version */
    }
    return (s >> 16) == 0xFFFFFFFFFFFFull && (s & 0xFFFFu) >= 1 && (s & 0xFFFFu) <= 0xFEFFu; /* group ID */
}

bool mt_acl_entry_valid(const mt_acl_entry *e)
{
    if (e->privilege < MT_ACL_PRIV_VIEW || e->privilege > MT_ACL_PRIV_ADMINISTER) return false;
    if (e->auth_mode != MT_ACL_AUTH_CASE && e->auth_mode != MT_ACL_AUTH_GROUP) return false;
    if (e->auth_mode == MT_ACL_AUTH_GROUP && e->privilege == MT_ACL_PRIV_ADMINISTER) return false;
    if (e->n_subjects > MT_ACL_MAX_SUBJECTS || e->n_targets > MT_ACL_MAX_TARGETS) return false;
    for (unsigned i = 0; i < e->n_subjects; i++)
        if (!subject_ok(e->auth_mode, e->subjects[i])) return false;
    for (unsigned i = 0; i < e->n_targets; i++) {
        const mt_acl_target *t = &e->targets[i];
        bool c = t->cluster != MT_ACL_NO_CLUSTER, ep = t->endpoint != MT_ACL_NO_ENDPOINT, d = t->devtype != MT_ACL_NO_DEVTYPE;
        if (!(c || ep || d) || (ep && d)) return false;
    }
    return true;
}

mt_err mt_acl_entry_encode(mt_tlv_wr *w, mt_tlv_tag tag, const mt_acl_entry *e)
{
    MT_TRY(mt_tlv_start(w, tag, MT_TLV_STRUCT));
    MT_TRY(mt_acl_entry_encode_fields(w, e));
    return mt_tlv_end(w);
}

mt_err mt_acl_entry_encode_fields(mt_tlv_wr *w, const mt_acl_entry *e)
{
    MT_TRY(mt_tlv_put_u(w, mt_tlv_ctx(1), e->privilege));
    MT_TRY(mt_tlv_put_u(w, mt_tlv_ctx(2), e->auth_mode));
    if (!e->n_subjects) MT_TRY(mt_tlv_put_null(w, mt_tlv_ctx(3)));
    else {
        MT_TRY(mt_tlv_start(w, mt_tlv_ctx(3), MT_TLV_ARRAY));
        for (unsigned i = 0; i < e->n_subjects; i++) MT_TRY(mt_tlv_put_u(w, mt_tlv_anon(), e->subjects[i]));
        MT_TRY(mt_tlv_end(w));
    }
    if (!e->n_targets) MT_TRY(mt_tlv_put_null(w, mt_tlv_ctx(4)));
    else {
        MT_TRY(mt_tlv_start(w, mt_tlv_ctx(4), MT_TLV_ARRAY));
        for (unsigned i = 0; i < e->n_targets; i++) {
            const mt_acl_target *t = &e->targets[i];
            MT_TRY(mt_tlv_start(w, mt_tlv_anon(), MT_TLV_STRUCT));
            if (t->cluster != MT_ACL_NO_CLUSTER) MT_TRY(mt_tlv_put_u(w, mt_tlv_ctx(0), t->cluster));
            else MT_TRY(mt_tlv_put_null(w, mt_tlv_ctx(0)));
            if (t->endpoint != MT_ACL_NO_ENDPOINT) MT_TRY(mt_tlv_put_u(w, mt_tlv_ctx(1), t->endpoint));
            else MT_TRY(mt_tlv_put_null(w, mt_tlv_ctx(1)));
            if (t->devtype != MT_ACL_NO_DEVTYPE) MT_TRY(mt_tlv_put_u(w, mt_tlv_ctx(2), t->devtype));
            else MT_TRY(mt_tlv_put_null(w, mt_tlv_ctx(2)));
            MT_TRY(mt_tlv_end(w));
        }
        MT_TRY(mt_tlv_end(w));
    }
    return MT_OK;
}

/* Container loop: calls body for each element; returns INVALID unless the container ended cleanly. */
#define EACH(r, e_) while (((e_) = mt_tlv_next(r)) == MT_OK)

static mt_err decode_target(mt_tlv_rd *r, mt_acl_target *t)
{
    mt_err e;
    t->cluster = MT_ACL_NO_CLUSTER; t->endpoint = MT_ACL_NO_ENDPOINT; t->devtype = MT_ACL_NO_DEVTYPE;
    if (r->type != MT_TLV_STRUCT) return MT_ERR_INVALID;
    MT_TRY(mt_tlv_enter(r));
    EACH(r, e) {
        if (r->tag.kind != MT_TAG_CTX || r->type == MT_TLV_NULL) continue;
        if (r->tag.num == 0) MT_TRY(mt_tlv_get_u32(r, &t->cluster));
        else if (r->tag.num == 1) MT_TRY(mt_tlv_get_u16(r, &t->endpoint));
        else if (r->tag.num == 2) MT_TRY(mt_tlv_get_u32(r, &t->devtype));
    }
    if (e != MT_ERR_NOT_FOUND) return MT_ERR_INVALID;
    return mt_tlv_exit(r);
}

mt_err mt_acl_entry_decode(mt_tlv_rd *r, mt_acl_entry *out)
{
    mt_acl_entry x = { 0 };
    mt_err e;
    unsigned seen = 0;
    if (r->type != MT_TLV_STRUCT) return MT_ERR_INVALID;
    MT_TRY(mt_tlv_enter(r));
    EACH(r, e) {
        if (r->tag.kind != MT_TAG_CTX) continue;
        switch (r->tag.num) {
        case 1: MT_TRY(mt_tlv_get_u8(r, &x.privilege)); seen |= 1; break;
        case 2: MT_TRY(mt_tlv_get_u8(r, &x.auth_mode)); seen |= 2; break;
        case 3:
            if (r->type == MT_TLV_NULL) break;
            if (r->type != MT_TLV_ARRAY) return MT_ERR_INVALID;
            MT_TRY(mt_tlv_enter(r));
            EACH(r, e) {
                if (x.n_subjects == MT_ACL_MAX_SUBJECTS) return MT_ERR_BUFFER_TOO_SMALL;
                MT_TRY(mt_tlv_get_u64(r, &x.subjects[x.n_subjects++]));
            }
            if (e != MT_ERR_NOT_FOUND) return MT_ERR_INVALID;
            MT_TRY(mt_tlv_exit(r));
            break;
        case 4:
            if (r->type == MT_TLV_NULL) break;
            if (r->type != MT_TLV_ARRAY) return MT_ERR_INVALID;
            MT_TRY(mt_tlv_enter(r));
            EACH(r, e) {
                if (x.n_targets == MT_ACL_MAX_TARGETS) return MT_ERR_BUFFER_TOO_SMALL;
                MT_TRY(decode_target(r, &x.targets[x.n_targets++]));
            }
            if (e != MT_ERR_NOT_FOUND) return MT_ERR_INVALID;
            MT_TRY(mt_tlv_exit(r));
            break;
        default: break;
        }
    }
    if (e != MT_ERR_NOT_FOUND || seen != 3) return MT_ERR_INVALID;
    MT_TRY(mt_tlv_exit(r));
    *out = x;
    return MT_OK;
}
