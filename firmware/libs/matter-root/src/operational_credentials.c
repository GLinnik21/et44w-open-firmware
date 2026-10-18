/* Operational Credentials cluster (0x3E, spec 1.3 section 11.18), see mt_root_comm.h.
 * Command rules and status codes as in connectedhomeip v1.3 operational-credentials-server.cpp. */
#include "root_priv.h"

enum { A_NOCS = 0, A_FABRICS = 1, A_SUPPORTED = 2, A_COMMISSIONED = 3, A_TRUSTED_ROOTS = 4, A_CURRENT = 5 };
enum {
    C_ATTEST = 0, C_ATTEST_RESP = 1, C_CHAIN = 2, C_CHAIN_RESP = 3, C_CSR = 4, C_CSR_RESP = 5, C_ADD_NOC = 6,
    C_UPDATE_NOC = 7, C_NOC_RESP = 8, C_LABEL = 9, C_REMOVE = 10, C_ADD_TRC = 11
};
enum { CHAIN_DAC = 1, CHAIN_PAI = 2 }; /* CertificateChainTypeEnum (11.18.4.2) */

#define V MT_IM_PRIV_VIEW
#define ADM MT_IM_PRIV_ADMINISTER
#define L MT_IM_ATTR_LIST

static const mt_dm_attr_def attrs[] = {
    { A_NOCS, L, ADM, 0 },
    { A_FABRICS, L, V, 0 },
    { A_SUPPORTED, MT_IM_ATTR_FIXED, V, 0 },
    { A_COMMISSIONED, 0, V, 0 },
    { A_TRUSTED_ROOTS, L, V, 0 },
    { A_CURRENT, 0, V, 0 },
};
static const mt_dm_cmd_def cmds[] = {
    { C_ATTEST, ADM, false }, { C_CHAIN, ADM, false }, { C_CSR, ADM, false }, { C_ADD_NOC, ADM, false },
    { C_UPDATE_NOC, ADM, false }, { C_LABEL, ADM, false }, { C_REMOVE, ADM, false }, { C_ADD_TRC, ADM, false },
};
static const uint32_t generated[] = { C_ATTEST_RESP, C_CHAIN_RESP, C_CSR_RESP, C_NOC_RESP };

/* ---- attributes ---- */

/* List item `item` of a fabric-scoped list after fabric filtering (7.13.6 / 8.4.3.2). */
static const mt_fabric *fabric_item(const mt_root *r, const mt_im_rctx *rc, uint16_t item)
{
    const mt_fabric *f;
    unsigned k = 0;
    for (unsigned n = 0; (f = mt_fabric_nth(r->c.fabrics, n)) != NULL; n++) {
        if (rc->fabric_filtered && f->index != rc->subj->fabric) continue;
        if (k++ == item) return f;
    }
    return NULL;
}

static mt_err put_cert(const mt_root *r, const mt_fabric *f, int kind, mt_tlv_wr *w, mt_tlv_tag tag, bool nullable)
{
    mt_span c;
    mt_err e = mt_fabric_read_cert(r->c.fabrics, f, kind, r->c.scratch, &c);
    if (e == MT_ERR_NOT_FOUND && nullable) return mt_tlv_put_null(w, tag);
    return e ? e : mt_tlv_put_bytes(w, tag, c);
}

/* NOCStruct (11.18.4.4): noc and icac are fabric-sensitive, so other fabrics' entries carry only the index. */
static mt_err put_noc(const mt_root *r, const mt_im_rctx *rc, const mt_fabric *f, mt_tlv_wr *w, mt_tlv_tag tag)
{
    mt_err e = mt_tlv_start(w, tag, MT_TLV_STRUCT);
    if (!e && f->index == rc->subj->fabric) {
        e = put_cert(r, f, MT_FKIND_NOC, w, CTX(1), false);
        if (!e) e = put_cert(r, f, MT_FKIND_ICAC, w, CTX(2), true);
    }
    if (!e) e = mt_tlv_put_u(w, CTX(TAG_FABRIC_INDEX), f->index);
    return e ? e : mt_tlv_end(w);
}

/* FabricDescriptorStruct (11.18.4.5): no fabric-sensitive fields. */
static mt_err put_fabric(const mt_fabric *f, mt_tlv_wr *w, mt_tlv_tag tag)
{
    mt_err e = mt_tlv_start(w, tag, MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_bytes(w, CTX(1), mt_span_of(f->root_pub, sizeof f->root_pub));
    if (!e) e = mt_tlv_put_u(w, CTX(2), f->vendor_id);
    if (!e) e = mt_tlv_put_u(w, CTX(3), f->fabric_id);
    if (!e) e = mt_tlv_put_u(w, CTX(4), f->node_id);
    if (!e) e = mt_tlv_put_utf8(w, CTX(5), f->label, strlen(f->label));
    if (!e) e = mt_tlv_put_u(w, CTX(TAG_FABRIC_INDEX), f->index);
    return e ? e : mt_tlv_end(w);
}

/* TrustedRootCertificates (11.18.5.5): the fabrics' roots, then a root staged by AddTrustedRootCertificate that
 * no AddNOC has used yet. */
static mt_err put_root(const mt_root *r, uint16_t item, mt_tlv_wr *w, mt_tlv_tag tag)
{
    const mt_fabric_table *t = r->c.fabrics;
    unsigned n = mt_fabric_count(t);
    if (item < n) return put_cert(r, mt_fabric_nth(t, item), MT_FKIND_RCAC, w, tag, false);
    if (item == n && t->pend.kind == MT_FABRIC_PEND_NONE && t->pend.rcac_len)
        return mt_tlv_put_bytes(w, tag, mt_span_of(t->pend.rcac, t->pend.rcac_len));
    return MT_ERR_NOT_FOUND;
}

static mt_err oc_read(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                      mt_tlv_tag tag)
{
    const mt_root *r = at->cl->ctx;
    const mt_fabric *f;
    mt_tlv_mark m = mt_tlv_wr_mark(w);
    mt_err e;
    switch (attr) {
    case A_NOCS:
        if (!(f = fabric_item(r, rc, item))) return MT_ERR_NOT_FOUND;
        e = put_noc(r, rc, f, w, tag);
        break;
    case A_FABRICS:
        if (!(f = fabric_item(r, rc, item))) return MT_ERR_NOT_FOUND;
        e = put_fabric(f, w, tag);
        break;
    case A_SUPPORTED: return mt_tlv_put_u(w, tag, MT_FABRIC_MAX);
    case A_COMMISSIONED: return mt_tlv_put_u(w, tag, mt_fabric_count(r->c.fabrics));
    case A_TRUSTED_ROOTS: e = put_root(r, item, w, tag); break;
    case A_CURRENT: return mt_tlv_put_u(w, tag, rc->subj->fabric);
    default: return MT_ERR_NOT_FOUND;
    }
    if (e) mt_tlv_wr_rollback(w, m);
    return e;
}

/* ---- commands ---- */

static mt_im_status bytes_field(mt_tlv_rd *f, uint8_t tag, mt_span *out)
{
    mt_tlv_rd x;
    return mt_im_field(f, tag, &x) || mt_tlv_get_bytes(&x, out) ? MT_IM_INVALID_COMMAND : MT_IM_SUCCESS;
}

/* NOCResponse (11.18.6.9): FabricIndex only with OK, no DebugText (as chip). */
static mt_im_status noc_response(mt_tlv_wr *resp, uint32_t *resp_cmd, uint8_t code, uint8_t index)
{
    if (mt_tlv_put_u(resp, CTX(0), code) || (code == MT_NOC_OK && mt_tlv_put_u(resp, CTX(1), index)))
        return MT_IM_RESOURCE_EXHAUSTED;
    *resp_cmd = C_NOC_RESP;
    return MT_IM_SUCCESS;
}

/* Elements and signature responses: {0: elements, 1: signature}, signature by the DAC over elements || the
 * session's AttestationChallenge (11.18.4.7 / 11.18.4.9). `msg` holds the elements at its start and has room for
 * the challenge behind them. */
static mt_im_status signed_response(mt_root *r, const mt_im_subject *s, mt_buf msg, size_t len, mt_tlv_wr *resp,
                                    uint32_t *resp_cmd, uint32_t cmd)
{
    mt_root_session ss;
    uint8_t sig[MT_P256_SIG_LEN];
    mt_err e;
    if (msg.cap - len < MT_ROOT_CHALLENGE_LEN) return MT_IM_RESOURCE_EXHAUSTED;
    if (!root_session(r, s->session, &ss)) return MT_IM_FAILURE;
    memcpy(msg.p + len, ss.challenge, MT_ROOT_CHALLENGE_LEN);
    e = r->c.creds->sign(r->c.creds->ctx, mt_span_of(msg.p, len + MT_ROOT_CHALLENGE_LEN), sig);
    mt_wipe(msg.p + len, MT_ROOT_CHALLENGE_LEN);
    mt_wipe(&ss, sizeof ss);
    if (e) return MT_IM_FAILURE;
    if (mt_tlv_put_bytes(resp, CTX(0), mt_span_of(msg.p, len)) || mt_tlv_put_bytes(resp, CTX(1), mt_span_of(sig, sizeof sig)))
        return MT_IM_RESOURCE_EXHAUSTED;
    *resp_cmd = cmd;
    return MT_IM_SUCCESS;
}

/* 11.18.6.1: AttestationElements = {1: CertificationDeclaration, 2: AttestationNonce, 3: Timestamp} (spec 6.2.4,
 * timestamp 0 = no time source; no firmware information). */
static mt_im_status attestation_request(mt_root *r, const mt_im_subject *s, mt_tlv_rd *f, mt_tlv_wr *resp,
                                        uint32_t *resp_cmd)
{
    mt_span nonce, el;
    mt_tlv_wr w;
    mt_err e;
    if (bytes_field(f, 0, &nonce) || nonce.len != MT_ROOT_NONCE_LEN) return MT_IM_INVALID_COMMAND;
    mt_tlv_wr_init(&w, r->c.scratch);
    e = mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_bytes(&w, CTX(1), r->c.creds->cd);
    if (!e) e = mt_tlv_put_bytes(&w, CTX(2), nonce);
    if (!e) e = mt_tlv_put_u(&w, CTX(3), 0);
    if (!e) e = mt_tlv_end(&w);
    if (!e) e = mt_tlv_wr_done(&w, &el);
    if (e) return MT_IM_RESOURCE_EXHAUSTED;
    return signed_response(r, s, r->c.scratch, el.len, resp, resp_cmd, C_ATTEST_RESP);
}

/* 11.18.6.3 */
static mt_im_status chain_request(mt_root *r, mt_tlv_rd *f, mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_tlv_rd x;
    uint8_t type;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_u8(&x, &type) || (type != CHAIN_DAC && type != CHAIN_PAI))
        return MT_IM_INVALID_COMMAND;
    if (mt_tlv_put_bytes(resp, CTX(0), type == CHAIN_DAC ? r->c.creds->dac : r->c.creds->pai))
        return MT_IM_RESOURCE_EXHAUSTED;
    *resp_cmd = C_CHAIN_RESP;
    return MT_IM_SUCCESS;
}

/* 11.18.6.5: a fresh operational key pair, staged in the fabric table until AddNOC/UpdateNOC or fail-safe end. */
static mt_im_status csr_request(mt_root *r, const mt_im_subject *s, mt_tlv_rd *f, mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_span nonce, el;
    mt_tlv_rd x;
    bool update = false;
    uint8_t priv[MT_P256_SCALAR_LEN], pub[MT_P256_POINT_LEN];
    mt_err e;
    if (bytes_field(f, 0, &nonce) || nonce.len != MT_ROOT_NONCE_LEN) return MT_IM_INVALID_COMMAND;
    if (!mt_im_field(f, 1, &x) && mt_tlv_get_bool(&x, &update)) return MT_IM_INVALID_COMMAND;
    if (update && !mt_fabric_get(r->c.fabrics, s->fabric)) return MT_IM_INVALID_COMMAND; /* PASE: no fabric */
    if (!root_fs_armed_for(r, s->fabric)) return MT_IM_FAILSAFE_REQUIRED;
    if (r->fs.flags & (MT_FS_ADD_NOC | MT_FS_UPDATE_NOC)) return MT_IM_CONSTRAINT_ERROR;
    e = r->c.ops->opkey_gen ? r->c.ops->opkey_gen(r->c.ctx, priv, pub) : mt_crypto_p256_keygen(r->c.rng, priv, pub);
    if (!e) e = mt_fabric_stage_key(r->c.fabrics, priv, pub);
    if (!e) e = mt_cert_build_nocsr_elements(r->c.rng, priv, pub, nonce.p, r->c.scratch, &el);
    mt_wipe(priv, sizeof priv);
    if (e) return MT_IM_FAILURE;
    r->fs.flags = (uint8_t)((r->fs.flags & ~MT_FS_CSR_UPDATE) | MT_FS_CSR | (update ? MT_FS_CSR_UPDATE : 0));
    return signed_response(r, s, r->c.scratch, el.len, resp, resp_cmd, C_CSR_RESP);
}

/* 11.18.6.13 */
static mt_im_status add_trusted_root(mt_root *r, const mt_im_subject *s, mt_tlv_rd *f)
{
    mt_span rcac;
    mt_err e;
    if (bytes_field(f, 0, &rcac) || rcac.len > MT_FABRIC_CERT_MAX) return MT_IM_INVALID_COMMAND;
    if (!root_fs_armed_for(r, s->fabric)) return MT_IM_FAILSAFE_REQUIRED;
    if (r->fs.flags & (MT_FS_ADD_TRC | MT_FS_ADD_NOC | MT_FS_UPDATE_NOC)) return MT_IM_CONSTRAINT_ERROR;
    e = mt_fabric_stage_rcac(r->c.fabrics, rcac);
    if (e == MT_ERR_INVALID || e == MT_ERR_UNSUPPORTED) return MT_IM_INVALID_COMMAND;
    if (e) return MT_IM_FAILURE;
    r->fs.flags |= MT_FS_ADD_TRC;
    root_changed(r, MT_OPCREDS_CLUSTER_ID, A_TRUSTED_ROOTS);
    return MT_IM_SUCCESS;
}

/* Is `id` an operational node ID or a CASE Authenticated Tag (spec 2.5.5, 6.6.2.1.2)? */
static bool admin_subject_ok(uint64_t id)
{
    if (id >= 1 && id <= MT_CERT_NODE_ID_MAX) return true;
    return (id >> 32) == 0xFFFFFFFDu && (id & 0xFFFFu) != 0; /* CAT with a non-zero version */
}

/* NOCResponse status of a failed AddNOC (index 0) or UpdateNOC (index = the fabric), in connectedhomeip v1.3 order:
 * FabricTable::AddNewPendingFabricCommon / UpdatePendingFabricCommon check table space, then the collision
 * (FindExistingFabricByNocChaining: NOC decode, CHIP_ERROR_WRONG_NODE_ID, FABRIC_EXISTS on AddNOC, another fabric
 * than `index` -> INVALID_FABRIC_INDEX on UpdateNOC), then AddOrUpdateInner validates the chain
 * (ValidateIncomingNOCChain: any error -> UNSUPPORTED_CERT_FORMAT = InvalidNOC) before the operational key
 * (INVALID_PUBLIC_KEY); ConvertToNOCResponseStatus maps everything else to InvalidNOC. */
static uint8_t noc_status(const mt_root *r, uint8_t index, mt_span noc, mt_span icac, mt_err e)
{
    mt_fabric_table *t = r->c.fabrics;
    const mt_fabric *f = index ? mt_fabric_get(t, index) : NULL;
    mt_cert n, root;
    if (e == MT_ERR_BUFFER_TOO_SMALL) return MT_NOC_TABLE_FULL;
    if (index && (e == MT_ERR_NOT_FOUND || !f)) return MT_NOC_INVALID_FABRIC_INDEX;
    if (mt_cert_decode(noc, &n)) return MT_NOC_INVALID_NOC;
    if (!(n.subject.has & MT_DN_HAS_NODE) || !n.subject.node_id || n.subject.node_id > MT_CERT_NODE_ID_MAX)
        return MT_NOC_INVALID_NODE_OP_ID;
    if (!(n.subject.has & MT_DN_HAS_FABRIC)) return MT_NOC_INVALID_NOC;
    if (index && n.subject.fabric_id != f->fabric_id) return MT_NOC_INVALID_FABRIC_INDEX;
    if (!index && t->pend.rcac_len && !mt_cert_decode(mt_span_of(t->pend.rcac, t->pend.rcac_len), &root) &&
        mt_fabric_conflict(t, root.pubkey.p, n.subject.fabric_id))
        return MT_NOC_FABRIC_CONFLICT;
    if (mt_fabric_check_chain(t, index, noc, icac, r->c.scratch)) return MT_NOC_INVALID_NOC;
    if (n.pubkey.len != MT_P256_POINT_LEN || memcmp(n.pubkey.p, t->pend.pub, MT_P256_POINT_LEN))
        return MT_NOC_INVALID_PUBLIC_KEY;
    return MT_NOC_INVALID_NOC;
}

/* NOCValue (0), optional ICACValue (1): both <= 400 bytes. */
static mt_im_status noc_fields(mt_tlv_rd *f, mt_span *noc, mt_span *icac)
{
    mt_tlv_rd x;
    *icac = mt_span_of(NULL, 0);
    if (bytes_field(f, 0, noc) || noc->len > MT_FABRIC_CERT_MAX) return MT_IM_INVALID_COMMAND;
    if (!mt_im_field(f, 1, &x) && (mt_tlv_get_bytes(&x, icac) || icac->len > MT_FABRIC_CERT_MAX))
        return MT_IM_INVALID_COMMAND;
    return MT_IM_SUCCESS;
}

/* 11.18.6.8 */
static mt_im_status add_noc(mt_root *r, const mt_im_subject *s, mt_tlv_rd *f, mt_tlv_wr *resp,
                            uint32_t *resp_cmd)
{
    mt_span noc, icac, ipk;
    mt_tlv_rd x;
    uint64_t admin;
    uint16_t vendor;
    uint8_t index = 0;
    mt_err e;
    if (noc_fields(f, &noc, &icac) || bytes_field(f, 2, &ipk) || ipk.len != MT_IPK_LEN || mt_im_field(f, 3, &x) ||
        mt_tlv_get_u64(&x, &admin) || mt_im_field(f, 4, &x) || mt_tlv_get_u16(&x, &vendor) || vendor == 0 ||
        vendor > 0xFFF4u /* IsVendorIdValidOperationally */)
        return MT_IM_INVALID_COMMAND;
    if (!root_fs_armed_for(r, s->fabric)) return MT_IM_FAILSAFE_REQUIRED;
    if (r->fs.flags & (MT_FS_ADD_NOC | MT_FS_UPDATE_NOC)) return MT_IM_CONSTRAINT_ERROR;
    if (!r->c.fabrics->pend.has_key) return noc_response(resp, resp_cmd, MT_NOC_MISSING_CSR, 0);
    if (r->fs.flags & MT_FS_CSR_UPDATE) return MT_IM_CONSTRAINT_ERROR;
    if (!(r->fs.flags & MT_FS_ADD_TRC)) return noc_response(resp, resp_cmd, MT_NOC_INVALID_NOC, 0);
    if (!admin_subject_ok(admin)) return noc_response(resp, resp_cmd, MT_NOC_INVALID_ADMIN_SUBJECT, 0);
    /* Validity is checked once the node knows the time (SetUTCTime / SNTP); until then now = 0 skips it. */
    e = mt_fabric_add_noc(r->c.fabrics, noc, icac, ipk.p, admin, vendor, mt_root_utc_now(r), r->c.scratch, &index);
    if (e) return noc_response(resp, resp_cmd, noc_status(r, 0, noc, icac, e), 0);
    if (s->auth == MT_IM_AUTH_PASE) r->c.ops->adopt_fabric(r->c.ctx, s->session, index);
    r->fs.fabric = index;
    r->fs.flags |= MT_FS_ADD_NOC;
    root_changed(r, MT_OPCREDS_CLUSTER_ID, MT_IM_WILD_ID);
    root_changed(r, MT_ACL_CLUSTER_ID, MT_IM_WILD_ID);
    root_event(r, MT_ROOT_EV_FABRIC_ADDED, index, s->session, r->fs.flags);
    return noc_response(resp, resp_cmd, MT_NOC_OK, index);
}

/* 11.18.6.10 (fabric-scoped) */
static mt_im_status update_noc(mt_root *r, const mt_im_subject *s, mt_tlv_rd *f, mt_tlv_wr *resp,
                               uint32_t *resp_cmd)
{
    mt_span noc, icac;
    mt_err e;
    if (!s->fabric) return MT_IM_UNSUPPORTED_ACCESS;
    if (noc_fields(f, &noc, &icac)) return MT_IM_INVALID_COMMAND;
    if (!root_fs_armed_for(r, s->fabric)) return MT_IM_FAILSAFE_REQUIRED;
    if (r->fs.flags & (MT_FS_ADD_NOC | MT_FS_UPDATE_NOC)) return MT_IM_CONSTRAINT_ERROR;
    if (!r->c.fabrics->pend.has_key) return noc_response(resp, resp_cmd, MT_NOC_MISSING_CSR, 0);
    if (!(r->fs.flags & MT_FS_CSR_UPDATE)) return MT_IM_CONSTRAINT_ERROR;
    e = mt_fabric_update_noc(r->c.fabrics, s->fabric, noc, icac, mt_root_utc_now(r), r->c.scratch);
    if (e) return noc_response(resp, resp_cmd, noc_status(r, s->fabric, noc, icac, e), 0);
    r->fs.flags |= MT_FS_UPDATE_NOC;
    root_changed(r, MT_OPCREDS_CLUSTER_ID, MT_IM_WILD_ID);
    root_event(r, MT_ROOT_EV_NOC_UPDATED, s->fabric, s->session, r->fs.flags);
    return noc_response(resp, resp_cmd, MT_NOC_OK, s->fabric);
}

/* 11.18.6.11 (fabric-scoped). The label must differ from every other fabric's label (committed or pending, whatever
 * their root or vendor), else NOCResponse LabelConflict (10) with no FabricIndex; the empty label never conflicts.
 * Same as rs-matter Fabrics::update_label and matter.js; connectedhomeip v1.3 source was not available to confirm.
 * Apple labels both of its fabrics "Home" (docs/matter-apple-trace.md) and still commissioned against rs-matter, which applies the
 * same rule (inferred: the conflict answer is tolerated; not yet seen on our device). */
static mt_im_status update_label(mt_root *r, const mt_im_subject *s, mt_tlv_rd *f,
                                 mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_tlv_rd x;
    mt_span label;
    if (!s->fabric) return MT_IM_UNSUPPORTED_ACCESS;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_utf8(&x, &label) || label.len > MT_FABRIC_LABEL_MAX)
        return MT_IM_INVALID_COMMAND;
    if (label.len && memchr(label.p, 0, label.len)) return MT_IM_CONSTRAINT_ERROR; /* stored as a C string */
    if (mt_fabric_label_in_use(r->c.fabrics, (const char *)label.p, label.len, s->fabric))
        return noc_response(resp, resp_cmd, MT_NOC_LABEL_CONFLICT, 0);
    if (mt_fabric_set_label(r->c.fabrics, s->fabric, (const char *)label.p, label.len, r->c.scratch))
        return MT_IM_FAILURE;
    root_changed(r, MT_OPCREDS_CLUSTER_ID, A_FABRICS);
    return noc_response(resp, resp_cmd, MT_NOC_OK, s->fabric);
}

/* 11.18.6.12. The sessions of the removed fabric are closed by the node after the response (MT_ROOT_EV_FABRIC_REMOVED);
 * a fail-safe armed for it ends first (its pending state belongs to the fabric). */
static mt_im_status remove_fabric(mt_root *r, const mt_im_subject *s, mt_tlv_rd *f,
                                  mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_tlv_rd x;
    uint8_t index;
    mt_err e;
    if (mt_im_field(f, 0, &x) || mt_tlv_get_u8(&x, &index) || index == 0 || index > MT_FABRIC_INDEX_MAX)
        return MT_IM_INVALID_COMMAND;
    if (!mt_fabric_get(r->c.fabrics, index)) return noc_response(resp, resp_cmd, MT_NOC_INVALID_FABRIC_INDEX, 0);
    if (r->fs.armed && r->fs.fabric == index) mt_root_failsafe_expire(r);
    e = mt_fabric_remove(r->c.fabrics, index);
    if (e && e != MT_ERR_NOT_FOUND) return MT_IM_FAILURE; /* NOT_FOUND: it was only pending, the expiry dropped it */
    root_changed(r, MT_OPCREDS_CLUSTER_ID, MT_IM_WILD_ID);
    root_changed(r, MT_ACL_CLUSTER_ID, MT_IM_WILD_ID);
    root_event(r, MT_ROOT_EV_FABRIC_REMOVED, index, s->session, 0);
    return noc_response(resp, resp_cmd, MT_NOC_OK, index);
}

static mt_im_status oc_invoke(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                              mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    mt_root *r = at->cl->ctx;
    switch (cmd) {
    case C_ATTEST: return attestation_request(r, s, fields, resp, resp_cmd);
    case C_CHAIN: return chain_request(r, fields, resp, resp_cmd);
    case C_CSR: return csr_request(r, s, fields, resp, resp_cmd);
    case C_ADD_TRC: return add_trusted_root(r, s, fields);
    case C_ADD_NOC: return add_noc(r, s, fields, resp, resp_cmd);
    case C_UPDATE_NOC: return update_noc(r, s, fields, resp, resp_cmd);
    case C_LABEL: return update_label(r, s, fields, resp, resp_cmd);
    case C_REMOVE: return remove_fabric(r, s, fields, resp, resp_cmd);
    default: return MT_IM_UNSUPPORTED_COMMAND;
    }
}

static const mt_dm_ops ops = { oc_read, NULL, oc_invoke };

void root_opcreds_init(mt_root *r)
{
    r->opcreds = (mt_dm_cluster){ .id = MT_OPCREDS_CLUSTER_ID, .revision = 1, .n_attrs = MT_DM_N(attrs),
                                  .n_cmds = MT_DM_N(cmds), .n_generated = MT_DM_N(generated), .attrs = attrs,
                                  .cmds = cmds, .generated = generated, .ops = &ops, .ctx = r };
}
