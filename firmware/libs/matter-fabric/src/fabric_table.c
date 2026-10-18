#include <string.h>
#include "fabric_internal.h"

#define PEND (t->pend)

static void pend_clear(mt_fabric_table *t)
{
    mt_wipe(&PEND, sizeof PEND);
}

void mt_fabric_init(mt_fabric_table *t, const mt_kv_ops *kv)
{
    memset(t, 0, sizeof *t);
    t->kv = kv;
}

static mt_fabric *slot_of(mt_fabric_table *t, uint8_t index)
{
    for (unsigned i = 0; index && i < MT_FABRIC_MAX; i++)
        if (t->slots[i].index == index) return &t->slots[i];
    return NULL;
}

mt_err mt_fabric_load(mt_fabric_table *t, mt_buf scratch)
{
    unsigned n = 0;
    t->skipped = 0;
    for (unsigned idx = 1; idx <= MT_FABRIC_INDEX_MAX; idx++) {
        size_t len;
        mt_err e = t->kv->get(t->kv->ctx, MT_FKEY(idx, MT_FKIND_META), scratch, &len);
        if (e == MT_ERR_NOT_FOUND) continue;
        if (e == MT_OK && n < MT_FABRIC_MAX) e = fabric_load_one(t->kv, (uint8_t)idx, &t->slots[n], scratch);
        else if (e == MT_OK) e = MT_ERR_BUFFER_TOO_SMALL;
        if (e == MT_OK) { n++; t->next_index = (uint8_t)idx; }
        else {
            t->skipped++;
            if (n < MT_FABRIC_MAX) memset(&t->slots[n], 0, sizeof t->slots[n]);
        }
    }
    return MT_OK;
}

/* ---- lookups ---- */

const mt_fabric *mt_fabric_nth(const mt_fabric_table *t, unsigned n)
{
    unsigned k = 0;
    for (unsigned i = 0; i < MT_FABRIC_MAX; i++) {
        const mt_fabric *f = &t->slots[i];
        if (!f->index) continue;
        if (PEND.kind == MT_FABRIC_PEND_UPDATE && PEND.fab.index == f->index) f = &PEND.fab;
        if (k++ == n) return f;
    }
    return PEND.kind == MT_FABRIC_PEND_NEW && k == n ? &PEND.fab : NULL;
}

unsigned mt_fabric_count(const mt_fabric_table *t)
{
    unsigned n = 0;
    while (mt_fabric_nth(t, n)) n++;
    return n;
}

unsigned mt_fabric_committed_count(const mt_fabric_table *t)
{
    unsigned n = 0;
    for (unsigned i = 0; i < MT_FABRIC_MAX; i++) n += t->slots[i].index != 0;
    return n;
}

const mt_fabric *mt_fabric_get(const mt_fabric_table *t, uint8_t index)
{
    const mt_fabric *f;
    for (unsigned n = 0; index && (f = mt_fabric_nth(t, n)) != NULL; n++)
        if (f->index == index) return f;
    return NULL;
}

int mt_fabric_pending_kind(const mt_fabric_table *t) { return PEND.kind; }
const mt_fabric *mt_fabric_pending(const mt_fabric_table *t) { return PEND.kind ? &PEND.fab : NULL; }

bool mt_fabric_conflict(const mt_fabric_table *t, const uint8_t root_pub[MT_P256_POINT_LEN], uint64_t fabric_id)
{
    const mt_fabric *f;
    for (unsigned n = 0; (f = mt_fabric_nth(t, n)) != NULL; n++)
        if (f->fabric_id == fabric_id && !memcmp(f->root_pub, root_pub, MT_P256_POINT_LEN)) return true;
    return false;
}

mt_err mt_fabric_read_cert(const mt_fabric_table *t, const mt_fabric *f, int kind, mt_buf out, mt_span *tlv)
{
    if (kind < MT_FKIND_RCAC || kind > MT_FKIND_NOC) return MT_ERR_INVALID;
    if (f->pending) {
        const uint8_t *p = kind == MT_FKIND_RCAC ? PEND.rcac : kind == MT_FKIND_ICAC ? PEND.icac : PEND.noc;
        size_t len = kind == MT_FKIND_RCAC ? PEND.rcac_len : kind == MT_FKIND_ICAC ? PEND.icac_len : PEND.noc_len;
        if (!len) return MT_ERR_NOT_FOUND;
        *tlv = mt_span_of(p, len);
        return MT_OK;
    }
    size_t len;
    MT_TRY(t->kv->get(t->kv->ctx, MT_FKEY(f->index, kind), out, &len));
    *tlv = mt_span_of(out.p, len);
    return MT_OK;
}

mt_err mt_fabric_read_opkey(const mt_fabric_table *t, const mt_fabric *f, uint8_t priv[MT_P256_SCALAR_LEN])
{
    if (f->pending) {
        memcpy(priv, PEND.priv, MT_P256_SCALAR_LEN);
        return MT_OK;
    }
    return fabric_read_priv(t->kv, f->index, priv);
}

/* ---- commissioning ---- */

mt_err mt_fabric_stage_key(mt_fabric_table *t, const uint8_t priv[MT_P256_SCALAR_LEN], const uint8_t pub[MT_P256_POINT_LEN])
{
    if (PEND.kind) return MT_ERR_STATE;
    if (pub[0] != 0x04) return MT_ERR_INVALID;
    memcpy(PEND.priv, priv, MT_P256_SCALAR_LEN);
    memcpy(PEND.pub, pub, MT_P256_POINT_LEN);
    PEND.has_key = true;
    return MT_OK;
}

mt_err mt_fabric_stage_rcac(mt_fabric_table *t, mt_span rcac)
{
    mt_cert c;
    if (PEND.kind || PEND.rcac_len) return MT_ERR_STATE;
    if (rcac.len == 0 || rcac.len > MT_FABRIC_CERT_MAX) return MT_ERR_INVALID;
    MT_TRY(mt_cert_decode(rcac, &c));
    MT_TRY(mt_cert_check_ca(&c, true));
    memcpy(PEND.rcac, rcac.p, rcac.len);
    PEND.rcac_len = (uint16_t)rcac.len;
    return MT_OK;
}

/* Decode RCAC, NOC and the optional ICAC (len 0 = none) and verify NOC -> [ICAC] -> RCAC; *n = NOC, *r = RCAC. */
static mt_err decode_chain(mt_span rcac, mt_span noc, mt_span icac, uint32_t now, mt_buf scratch, mt_cert *n, mt_cert *r)
{
    mt_cert i;
    MT_TRY(mt_cert_decode(rcac, r));
    MT_TRY(mt_cert_decode(noc, n));
    if (icac.len) MT_TRY(mt_cert_decode(icac, &i));
    return mt_cert_verify_chain(n, icac.len ? &i : NULL, r, now, scratch);
}

/* Verify noc[/icac] against the staged RCAC and the staged key; on success the NOC's identity is in
 * *fabric_id / *node_id and the root public key in root_pub. */
static mt_err verify_staged(mt_fabric_table *t, mt_span noc, mt_span icac, uint32_t now, mt_buf scratch,
                            uint64_t *fabric_id, uint64_t *node_id, uint8_t root_pub[MT_P256_POINT_LEN])
{
    mt_cert n, r;
    if (!PEND.has_key || !PEND.rcac_len) return MT_ERR_STATE;
    if (noc.len == 0 || noc.len > MT_FABRIC_CERT_MAX || icac.len > MT_FABRIC_CERT_MAX) return MT_ERR_INVALID;
    MT_TRY(decode_chain(mt_span_of(PEND.rcac, PEND.rcac_len), noc, icac, now, scratch, &n, &r));
    if (!mt_span_eq(n.pubkey, mt_span_of(PEND.pub, MT_P256_POINT_LEN))) return MT_ERR_INVALID;
    *fabric_id = n.subject.fabric_id;
    *node_id = n.subject.node_id;
    memcpy(root_pub, r.pubkey.p, MT_P256_POINT_LEN);
    return MT_OK;
}

static void pend_set_certs(mt_fabric_table *t, mt_span noc, mt_span icac)
{
    memcpy(PEND.noc, noc.p, noc.len);
    PEND.noc_len = (uint16_t)noc.len;
    if (icac.len) memcpy(PEND.icac, icac.p, icac.len);
    PEND.icac_len = (uint16_t)icac.len;
}

mt_err mt_fabric_add_noc(mt_fabric_table *t, mt_span noc, mt_span icac, const uint8_t ipk_epoch[MT_IPK_LEN],
                         uint64_t admin_subject, uint16_t admin_vendor, uint32_t now, mt_buf scratch, uint8_t *index)
{
    uint64_t fid, nid;
    uint8_t root[MT_P256_POINT_LEN];
    mt_fabric *f = &PEND.fab;
    mt_acl_entry admin = { MT_ACL_PRIV_ADMINISTER, MT_ACL_AUTH_CASE, 1, 0, { admin_subject }, { { 0 } } };
    unsigned idx = 0;
    if (PEND.kind) return MT_ERR_STATE;
    if (mt_fabric_committed_count(t) >= MT_FABRIC_MAX) return MT_ERR_BUFFER_TOO_SMALL;
    if (!mt_acl_entry_valid(&admin)) return MT_ERR_INVALID;
    MT_TRY(verify_staged(t, noc, icac, now, scratch, &fid, &nid, root));
    if (mt_fabric_conflict(t, root, fid)) return MT_ERR_INVALID;
    for (unsigned s = 0; s < MT_FABRIC_INDEX_MAX && !idx; s++) {
        unsigned cand = ((unsigned)t->next_index + s) % MT_FABRIC_INDEX_MAX + 1;
        if (!slot_of(t, (uint8_t)cand)) idx = cand;
    }
    memset(f, 0, sizeof *f);
    f->index = (uint8_t)idx;
    f->pending = true;
    f->vendor_id = admin_vendor;
    f->fabric_id = fid;
    f->node_id = nid;
    memcpy(f->root_pub, root, MT_P256_POINT_LEN);
    memcpy(f->ipk_epoch, ipk_epoch, MT_IPK_LEN);
    f->n_acl = 1;
    f->acl[0] = admin;
    mt_err e = fabric_derive(f);
    if (e) { memset(f, 0, sizeof *f); return e; }
    pend_set_certs(t, noc, icac);
    PEND.kind = MT_FABRIC_PEND_NEW;
    t->next_index = f->index;
    *index = f->index;
    return MT_OK;
}

mt_err mt_fabric_update_noc(mt_fabric_table *t, uint8_t index, mt_span noc, mt_span icac, uint32_t now, mt_buf scratch)
{
    uint64_t fid, nid;
    uint8_t root[MT_P256_POINT_LEN];
    size_t len;
    mt_fabric *old = slot_of(t, index);
    if (PEND.kind || PEND.rcac_len) return MT_ERR_STATE;
    if (!old) return MT_ERR_NOT_FOUND;
    MT_TRY(t->kv->get(t->kv->ctx, MT_FKEY(index, MT_FKIND_RCAC), mt_buf_of(PEND.rcac, sizeof PEND.rcac), &len));
    PEND.rcac_len = (uint16_t)len;
    mt_err e = verify_staged(t, noc, icac, now, scratch, &fid, &nid, root);
    if (!e && (fid != old->fabric_id || memcmp(root, old->root_pub, MT_P256_POINT_LEN))) e = MT_ERR_INVALID;
    if (e) { PEND.rcac_len = 0; return e; }
    PEND.fab = *old;
    PEND.fab.pending = true;
    PEND.fab.node_id = nid;
    pend_set_certs(t, noc, icac);
    PEND.kind = MT_FABRIC_PEND_UPDATE;
    return MT_OK;
}

mt_err mt_fabric_check_chain(mt_fabric_table *t, uint8_t index, mt_span noc, mt_span icac, mt_buf scratch)
{
    mt_cert n, r;
    size_t len = PEND.rcac_len;
    if (index) {
        if (PEND.kind || PEND.rcac_len) return MT_ERR_STATE;
        if (!slot_of(t, index)) return MT_ERR_NOT_FOUND;
        MT_TRY(t->kv->get(t->kv->ctx, MT_FKEY(index, MT_FKIND_RCAC), mt_buf_of(PEND.rcac, sizeof PEND.rcac), &len));
    } else if (!len) {
        return MT_ERR_STATE;
    }
    return decode_chain(mt_span_of(PEND.rcac, len), noc, icac, 0, scratch, &n, &r);
}

mt_err mt_fabric_commit(mt_fabric_table *t, mt_buf scratch)
{
    const uint8_t *certs[3] = { PEND.rcac, PEND.icac, PEND.noc };
    const uint16_t lens[3] = { PEND.rcac_len, PEND.icac_len, PEND.noc_len };
    mt_fabric *slot = NULL;
    if (!PEND.kind) return MT_ERR_STATE;
    if (PEND.kind == MT_FABRIC_PEND_UPDATE) slot = slot_of(t, PEND.fab.index);
    else
        for (unsigned i = 0; i < MT_FABRIC_MAX && !slot; i++)
            if (!t->slots[i].index) slot = &t->slots[i];
    if (!slot) return MT_ERR_STATE;
    MT_TRY(fabric_persist(t->kv, &PEND.fab, PEND.priv, certs, lens, scratch));
    *slot = PEND.fab;
    slot->pending = false;
    pend_clear(t);
    return MT_OK;
}

void mt_fabric_abort(mt_fabric_table *t)
{
    pend_clear(t);
}

/* ---- changes to existing fabrics ---- */

mt_err mt_fabric_remove(mt_fabric_table *t, uint8_t index)
{
    mt_fabric *s = slot_of(t, index);
    if (!s) {
        if (PEND.kind == MT_FABRIC_PEND_NEW && PEND.fab.index == index) { pend_clear(t); return MT_OK; }
        return MT_ERR_NOT_FOUND;
    }
    MT_TRY(fabric_erase(t->kv, index));
    if (PEND.kind == MT_FABRIC_PEND_UPDATE && PEND.fab.index == index) pend_clear(t);
    mt_wipe(s, sizeof *s);
    return MT_OK;
}

/* An edit of ACL or label, applied to the committed copy (persisting it) and to the staged one of the same index. */
typedef struct { bool is_acl; const mt_acl_entry *acl; unsigned n_acl; const char *label; size_t label_len; } edit;

static void apply(mt_fabric *f, const edit *ed)
{
    if (ed->is_acl) {
        for (unsigned i = 0; i < ed->n_acl; i++) f->acl[i] = ed->acl[i];
        f->n_acl = (uint8_t)ed->n_acl;
    } else {
        memcpy(f->label, ed->label, ed->label_len);
        f->label[ed->label_len] = 0;
    }
}

static mt_err change(mt_fabric_table *t, uint8_t index, const edit *ed, mt_buf scratch)
{
    mt_fabric *s = slot_of(t, index);
    bool staged = PEND.kind && PEND.fab.index == index;
    if (!s && !staged) return MT_ERR_NOT_FOUND;
    if (s) {
        mt_fabric copy = *s;
        apply(&copy, ed);
        MT_TRY(fabric_persist(t->kv, &copy, NULL, NULL, NULL, scratch));
        *s = copy;
    }
    if (staged) apply(&PEND.fab, ed);
    return MT_OK;
}

mt_err mt_fabric_acl_set(mt_fabric_table *t, uint8_t index, const mt_acl_entry *e, unsigned n, mt_buf scratch)
{
    if (n > MT_ACL_MAX_ENTRIES) return MT_ERR_BUFFER_TOO_SMALL;
    for (unsigned i = 0; i < n; i++)
        if (!mt_acl_entry_valid(&e[i])) return MT_ERR_INVALID;
    edit ed = { true, e, n, NULL, 0 };
    return change(t, index, &ed, scratch);
}

bool mt_fabric_label_in_use(const mt_fabric_table *t, const char *label, size_t len, uint8_t except_index)
{
    const mt_fabric *f;
    if (!len) return false; /* an empty label is "no label": never a conflict (rs-matter; chip's check is on labels set) */
    for (unsigned n = 0; (f = mt_fabric_nth(t, n)) != NULL; n++)
        if (f->index != except_index && strlen(f->label) == len && !memcmp(f->label, label, len)) return true;
    return false;
}

mt_err mt_fabric_set_label(mt_fabric_table *t, uint8_t index, const char *label, size_t len, mt_buf scratch)
{
    /* labels are C strings in RAM and in the META record: an embedded NUL would truncate them */
    if (len > MT_FABRIC_LABEL_MAX || (len && memchr(label, 0, len)) || mt_fabric_label_in_use(t, label, len, index))
        return MT_ERR_INVALID;
    edit ed = { false, NULL, 0, label, len };
    return change(t, index, &ed, scratch);
}
