/* CASE responder state machine and key schedule (Matter spec 4.14.2).
 *
 * Transcript: every hash input is the raw TLV payload of a Sigma message exactly as received or sent
 * (no message or protocol header). A running SHA-256 is kept; intermediate digests are peeked from it.
 *
 * Key schedule (spec 4.14.2, all HKDF-SHA256 with ikm = the ECDH shared secret, AES-128-CCM with a 13-byte
 * nonce, a 16-byte MIC and no associated data):
 *   S2K         = HKDF(salt = IPK || responderRandom || responderEphPubKey || SHA256(Sigma1),           info "Sigma2", 16)
 *   S3K         = HKDF(salt = IPK || SHA256(Sigma1 || Sigma2),                                          info "Sigma3", 16)
 *   I2R||R2I||AC = HKDF(salt = IPK || SHA256(Sigma1 || Sigma2 || Sigma3),                         info "SessionKeys", 48)
 *   TBEData2 nonce "NCASE_Sigma2N", TBEData3 nonce "NCASE_Sigma3N".
 * IPK is the fabric's operational group key (matter-fabric derives it from the epoch key). */
#include "mt_case.h"

#include <string.h>

#include "case_internal.h"

#define SC MT_P256_SCALAR_LEN
#define PT MT_P256_POINT_LEN
#define GENERAL_SUCCESS 0
#define GENERAL_FAILURE 1

_Static_assert(MT_CASE_WORK >= 2 * MT_CASE_CERT_MAX, "work holds a stored NOC and ICAC");
_Static_assert(MT_CASE_WORK >= 2 * (MT_CASE_CERT_MAX + 4) + 2 * (3 + PT) + 2, "work holds TBSData3");
_Static_assert(MT_CASE_WORK >= 2 * (MT_CASE_CERT_MAX + 4) + (3 + MT_P256_SIG_LEN) + (3 + MT_CASE_RESUMPTION_ID_LEN) + 2 +
                   MT_CCM_TAG_LEN, "work holds the TBEData2 ciphertext");
_Static_assert(MT_CASE_OUT_MIN >= 2 * (MT_CASE_CERT_MAX + 4) + (3 + MT_P256_SIG_LEN) + (3 + MT_CASE_RESUMPTION_ID_LEN) + 2 +
                   MT_CCM_TAG_LEN + 4 + (3 + CASE_RANDOM_LEN) + 4 + (3 + PT) + 2 + 40, "out holds the largest Sigma2");

static const uint8_t NONCE2[MT_CCM_NONCE_LEN] = { 'N', 'C', 'A', 'S', 'E', '_', 'S', 'i', 'g', 'm', 'a', '2', 'N' };
static const uint8_t NONCE3[MT_CCM_NONCE_LEN] = { 'N', 'C', 'A', 'S', 'E', '_', 'S', 'i', 'g', 'm', 'a', '3', 'N' };

void mt_case_init(mt_case *c, const mt_case_config *cfg, mt_rng *rng, uint16_t local_session_id, uint32_t now)
{
    memset(c, 0, sizeof *c);
    c->cfg = cfg;
    c->rng = rng;
    c->local_session_id = local_session_id;
    c->now = now;
}

void mt_case_reset(mt_case *c)
{
    const mt_case_config *cfg = c->cfg;
    mt_rng *rng = c->rng;
    uint16_t sid = c->local_session_id;
    uint32_t now = c->now;
    mt_wipe(c, sizeof *c);
    mt_case_init(c, cfg, rng, sid, now);
}

/* HKDF(salt = IPK || parts..., ikm = shared secret, info). Salt is at most IPK + random + point + hash. */
static mt_err kdf(const mt_case *c, const mt_span *parts, size_t n_parts, const char *info, uint8_t *okm, size_t len)
{
    uint8_t salt[MT_IPK_LEN + CASE_RANDOM_LEN + PT + MT_SHA256_LEN];
    size_t used = MT_IPK_LEN;
    memcpy(salt, c->ipk, MT_IPK_LEN);
    for (size_t i = 0; i < n_parts; i++) {
        if (parts[i].len > sizeof salt - used) return MT_ERR_INVALID;
        memcpy(salt + used, parts[i].p, parts[i].len);
        used += parts[i].len;
    }
    mt_err e = mt_crypto_hkdf_sha256(mt_span_of(salt, used), mt_span_of(c->shared, SC), mt_span_of(info, strlen(info)),
                                     mt_buf_of(okm, len));
    mt_wipe(salt, sizeof salt);
    return e;
}

/* ---- Sigma1 -> Sigma2 ---- */

/* The fabric's NOC and ICAC: a pending fabric's point into the table, a committed one's are read into
 * work[0, 2 * CERT_MAX). icac.len = 0 when the fabric has none. */
static mt_err read_own_certs(const mt_case *c, const mt_fabric *f, mt_buf work, mt_span *noc, mt_span *icac)
{
    if (work.cap < 2 * MT_CASE_CERT_MAX) return MT_ERR_BUFFER_TOO_SMALL;
    const mt_fabric_table *t = c->cfg->fabrics;
    mt_err e = mt_fabric_read_cert(t, f, MT_FKIND_NOC, mt_buf_of(work.p, MT_CASE_CERT_MAX), noc);
    if (e) return e == MT_ERR_NOT_FOUND ? MT_ERR_IO : e; /* a fabric without its NOC: damaged storage */
    e = mt_fabric_read_cert(t, f, MT_FKIND_ICAC, mt_buf_of(work.p + MT_CASE_CERT_MAX, MT_CASE_CERT_MAX), icac);
    if (e == MT_ERR_NOT_FOUND) *icac = mt_span_of(NULL, 0);
    else if (e) return e;
    return noc->len > MT_CASE_CERT_MAX || icac->len > MT_CASE_CERT_MAX ? MT_ERR_INVALID : MT_OK;
}

/* Remember the matched fabric's identity and keys. */
static void bind_fabric(mt_case *c, const mt_fabric *f)
{
    c->fabric_index = f->index;
    c->fabric_id = f->fabric_id;
    c->node_id = f->node_id;
    memcpy(c->cfid, f->cfid, MT_CFID_LEN);
    memcpy(c->ipk, f->ipk, MT_IPK_LEN);
}

/* Ephemeral key pair and ECDH; the private key never leaves this function. */
static mt_err ephemeral(mt_case *c, const uint8_t peer[PT])
{
    uint8_t priv[SC];
    mt_err e = mt_crypto_p256_keygen(c->rng, priv, c->eph_pub);
    if (!e) e = mt_crypto_p256_ecdh(c->rng, priv, peer, c->shared);
    mt_wipe(priv, sizeof priv);
    return e;
}

/* signature = ECDSA(node operational key, TBSData2), TBSData2 built in out. */
static mt_err sign_tbs2(mt_case *c, const mt_fabric *f, mt_span noc, mt_span icac, mt_buf out, uint8_t sig[MT_P256_SIG_LEN])
{
    uint8_t priv[SC];
    mt_span tbs;
    mt_err e = case_build_tbs(noc, icac, c->eph_pub, c->peer_eph_pub, out, &tbs);
    if (!e) e = mt_fabric_read_opkey(c->cfg->fabrics, f, priv);
    if (!e) e = mt_crypto_p256_sign(c->rng, priv, tbs, sig);
    mt_wipe(priv, sizeof priv);
    return e;
}

static mt_err on_sigma1(mt_case *c, mt_span payload, mt_buf out, mt_buf work, mt_case_reply *rep)
{
    case_sigma1 s;
    const mt_fabric *f;
    uint8_t random[CASE_RANDOM_LEN], rid[MT_CASE_RESUMPTION_ID_LEN], h1[MT_SHA256_LEN], s2k[MT_CASE_KEY_LEN];
    uint8_t sig[MT_P256_SIG_LEN];
    mt_span noc, icac, tbe, sigma2;
    size_t ct_len = 0;

    MT_TRY(case_parse_sigma1(payload, &s)); /* resumption fields are ignored: always a full Sigma2 */
    MT_TRY(mt_fabric_match_destination(c->cfg->fabrics, s.random, s.dest_id, &f));
    bind_fabric(c, f);
    c->peer_session_id = s.session_id;
    c->peer = s.peer;
    memcpy(c->peer_eph_pub, s.eph_pub, PT);

    mt_err e = ephemeral(c, s.eph_pub);  /* rejects an invalid initiator key */
    if (!e) e = mt_rng_fill(c->rng, random, sizeof random);
    if (!e) e = mt_rng_fill(c->rng, rid, sizeof rid);
    if (e) return e;

    mt_sha256_begin(&c->tt);
    mt_sha256_update(&c->tt, payload);
    mt_sha256_peek(&c->tt, h1);
    const mt_span s2k_salt[3] = { mt_span_of(random, sizeof random), mt_span_of(c->eph_pub, PT), mt_span_of(h1, sizeof h1) };
    e = kdf(c, s2k_salt, 3, "Sigma2", s2k, sizeof s2k);

    /* Buffers: certs in work, TBSData2 then TBEData2 in out, TBEData2 ciphertext into work (the certs are
     * no longer needed then), finally Sigma2 in out. */
    if (!e) e = read_own_certs(c, f, work, &noc, &icac);
    if (!e) e = sign_tbs2(c, f, noc, icac, out, sig);
    if (!e) e = case_build_tbe2(noc, icac, sig, rid, out, &tbe);
    if (!e) e = mt_crypto_ccm_encrypt(s2k, NONCE2, mt_span_of(NULL, 0), tbe, work, &ct_len);
    if (!e) e = case_build_sigma2(random, c->local_session_id, c->eph_pub, mt_span_of(work.p, ct_len), &c->cfg->params,
                                  out, &sigma2);
    mt_wipe(s2k, sizeof s2k);
    if (e) return e;

    mt_sha256_update(&c->tt, sigma2);
    c->state = MT_CASE_WAIT_SIGMA3;
    rep->opcode = MT_CASE_OP_SIGMA2;
    rep->len = sigma2.len;
    return MT_OK;
}

/* ---- Sigma3 ---- */

/* The fabric matched at Sigma1, if it is still there unchanged (it may have been removed, or the pending
 * fabric aborted or committed meanwhile; a commit keeps it valid). */
static const mt_fabric *bound_fabric(const mt_case *c)
{
    const mt_fabric *f = mt_fabric_get(c->cfg->fabrics, c->fabric_index);
    if (!f || f->fabric_id != c->fabric_id || f->node_id != c->node_id || memcmp(f->cfid, c->cfid, MT_CFID_LEN) ||
        memcmp(f->ipk, c->ipk, MT_IPK_LEN))
        return NULL;
    return f;
}

/* Verify the initiator: TBSData3 signature with its NOC key, then NOC -> [ICAC] -> our stored RCAC for the
 * same fabric. work: TBSData3, then RCAC in [0, CERT_MAX) and the chain scratch after it. */
static mt_err verify_initiator(mt_case *c, const mt_fabric *f, const case_tbe3 *t, mt_buf work)
{
    mt_cert noc, icac, rcac;
    mt_span tbs, root;
    MT_TRY(mt_cert_decode(t->noc, &noc));
    if (t->icac.len) MT_TRY(mt_cert_decode(t->icac, &icac));
    MT_TRY(case_build_tbs(t->noc, t->icac, c->peer_eph_pub, c->eph_pub, work, &tbs));
    MT_TRY(mt_crypto_p256_verify(noc.pubkey.p, tbs, t->sig));

    if (work.cap < MT_CASE_CERT_MAX + MT_CERT_SCRATCH) return MT_ERR_BUFFER_TOO_SMALL;
    mt_err e = mt_fabric_read_cert(c->cfg->fabrics, f, MT_FKIND_RCAC, mt_buf_of(work.p, MT_CASE_CERT_MAX), &root);
    if (e) return e == MT_ERR_NOT_FOUND ? MT_ERR_IO : e;
    MT_TRY(mt_cert_decode(root, &rcac));
    if (!mt_span_eq(rcac.pubkey, mt_span_of(f->root_pub, PT))) return MT_ERR_INVALID;
    MT_TRY(mt_cert_verify_chain(&noc, t->icac.len ? &icac : NULL, &rcac, c->now,
                             mt_buf_of(work.p + MT_CASE_CERT_MAX, work.cap - MT_CASE_CERT_MAX)));
    /* The chain check only compares fabric IDs inside the chain (Root01 has none): the peer must be on
     * our fabric. */
    if (noc.subject.fabric_id != f->fabric_id) return MT_ERR_INVALID;

    c->peer_node_id = noc.subject.node_id;
    c->n_peer_cats = noc.subject.n_cats;
    memcpy(c->peer_cats, noc.subject.cats, sizeof c->peer_cats);
    return MT_OK;
}

static mt_err on_sigma3(mt_case *c, mt_span payload, mt_buf out, mt_buf work, mt_case_reply *rep)
{
    mt_span enc;
    case_tbe3 t;
    uint8_t h[MT_SHA256_LEN], s3k[MT_CASE_KEY_LEN];
    size_t len = 0;
    const mt_fabric *f = bound_fabric(c);
    if (!f) return MT_ERR_NOT_FOUND;

    MT_TRY(case_parse_sigma3(payload, &enc));
    if (enc.len - MT_CCM_TAG_LEN > out.cap) return MT_ERR_INVALID;
    mt_sha256_peek(&c->tt, h); /* SHA256(Sigma1 || Sigma2) */
    const mt_span s3k_salt[1] = { mt_span_of(h, sizeof h) };
    mt_err e = kdf(c, s3k_salt, 1, "Sigma3", s3k, sizeof s3k);
    if (!e) e = mt_crypto_ccm_decrypt(s3k, NONCE3, mt_span_of(NULL, 0), enc, out, &len);
    mt_wipe(s3k, sizeof s3k);
    if (!e) e = case_parse_tbe3(mt_span_of(out.p, len), &t);
    if (!e) e = verify_initiator(c, f, &t, work);
    if (e) return e;

    mt_sha256_update(&c->tt, payload);
    mt_sha256_finish(&c->tt, h); /* SHA256(Sigma1 || Sigma2 || Sigma3) */
    const mt_span sk_salt[1] = { mt_span_of(h, sizeof h) };
    MT_TRY(kdf(c, sk_salt, 1, "SessionKeys", c->keys, sizeof c->keys));
    mt_wipe(c->shared, sizeof c->shared);
    MT_TRY(mt_sc_status(GENERAL_SUCCESS, MT_CASE_CODE_SUCCESS, out, &rep->len));
    c->state = MT_CASE_ESTABLISHED;
    rep->opcode = MT_CASE_OP_STATUS;
    return MT_OK;
}

/* A StatusReport from the initiator (e.g. it rejected our Sigma2) ends the handshake without a reply. */
static mt_err on_status(mt_case *c, mt_span payload)
{
    if (payload.len >= MT_SC_STATUS_LEN) {
        c->peer_general = mt_get_le16(payload.p);
        c->peer_protocol = mt_get_le32(payload.p + 2);
        c->peer_code = mt_get_le16(payload.p + 6);
    }
    return MT_ERR_STATE;
}

static mt_err dispatch(mt_case *c, uint8_t opcode, mt_span payload, mt_buf out, mt_buf work, mt_case_reply *rep)
{
    if (c->state == MT_CASE_IDLE && opcode == MT_CASE_OP_SIGMA1) return on_sigma1(c, payload, out, work, rep);
    if (c->state == MT_CASE_WAIT_SIGMA3 && opcode == MT_CASE_OP_SIGMA3) return on_sigma3(c, payload, out, work, rep);
    return MT_ERR_STATE;
}

mt_err mt_case_recv(mt_case *c, uint8_t opcode, mt_span payload, mt_buf out, mt_buf work, mt_case_reply *reply)
{
    reply->opcode = 0;
    reply->len = 0;
    if (c->state == MT_CASE_ESTABLISHED || c->state == MT_CASE_FAILED) return MT_ERR_STATE;
    if (opcode == MT_CASE_OP_STATUS) {
        mt_case_reset(c);
        c->state = MT_CASE_FAILED;
        return on_status(c, payload);
    }
    mt_err e = dispatch(c, opcode, payload, out, work, reply);
    if (e == MT_OK) return e;
    mt_case_reset(c);
    c->state = MT_CASE_FAILED;
    reply->len = 0;
    uint16_t code = e == MT_ERR_NOT_FOUND ? MT_CASE_CODE_NO_SHARED_ROOT : MT_CASE_CODE_INVALID_PARAM;
    if (mt_sc_status(GENERAL_FAILURE, code, out, &reply->len) == MT_OK) reply->opcode = MT_CASE_OP_STATUS;
    return e;
}

mt_err mt_case_session_keys(const mt_case *c, mt_case_session *out)
{
    if (c->state != MT_CASE_ESTABLISHED) return MT_ERR_STATE;
    memcpy(out->i2r, c->keys, MT_CASE_KEY_LEN);
    memcpy(out->r2i, c->keys + MT_CASE_KEY_LEN, MT_CASE_KEY_LEN);
    memcpy(out->attestation_challenge, c->keys + 2 * MT_CASE_KEY_LEN, MT_CASE_KEY_LEN);
    out->local_session_id = c->local_session_id;
    out->peer_session_id = c->peer_session_id;
    out->fabric_index = c->fabric_index;
    out->local_node_id = c->node_id;
    out->peer_node_id = c->peer_node_id;
    memcpy(out->peer_cats, c->peer_cats, sizeof out->peer_cats);
    out->n_peer_cats = c->n_peer_cats;
    out->peer = c->peer;
    return MT_OK;
}
