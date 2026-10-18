/* See case_ini.h. */
#include <string.h>

#include "case_ini.h"
#include "keys.h"
#include "mt_cert.h"
#include "vectors.h"

enum { OP_SIGMA1 = 0x30, OP_SIGMA2 = 0x31, OP_SIGMA3 = 0x32, OP_STATUS = 0x40 };

mt_span ci_root01(void) { return mt_span_of(v_Root01_tlv, sizeof v_Root01_tlv); }
mt_span ci_noc_device(void) { return mt_span_of(v_Node01_02_tlv, sizeof v_Node01_02_tlv); }
void ci_device_key(uint8_t priv[MT_P256_SCALAR_LEN], uint8_t pub[MT_P256_POINT_LEN])
{
    memcpy(priv, k_Node01_02_priv, MT_P256_SCALAR_LEN);
    memcpy(pub, v_Node01_02_pub, MT_P256_POINT_LEN);
}

typedef struct {
    uint64_t peer_node, fabric_id;
    uint8_t ipk[16], root_pub[65];
    uint8_t eph_priv[32], eph_pub[65], random[32];
    uint8_t s1[200], s2[1100], s3[1100];
    size_t s1_len, s2_len, s3_len;
    uint8_t peer_eph[65], shared[32];
    uint16_t peer_sid;
} ini;

static mt_err hkdf(const uint8_t *salt, size_t salt_len, const uint8_t ikm[32], const char *info, uint8_t *out, size_t n)
{
    return mt_crypto_hkdf_sha256(mt_span_of(salt, salt_len), mt_span_of(ikm, 32), mt_span_of(info, strlen(info)),
                                 mt_buf_of(out, n));
}

/* Sigma1 = { 1 initiatorRandom, 2 initiatorSessionId, 3 destinationId, 4 initiatorEphPubKey } */
static mt_err sigma1(ini *I, mt_rng *rng, uint16_t sid)
{
    uint8_t m[32 + 65 + 16], d[32];
    mt_tlv_wr w;
    mt_span s;
    if (mt_crypto_p256_keygen(rng, I->eph_priv, I->eph_pub) || mt_rng_fill(rng, I->random, 32)) return MT_ERR_CRYPTO;
    /* destinationId = HMAC-SHA256(IPK, random || rootPublicKey || fabricId LE64 || nodeId LE64) (4.14.2.4) */
    memcpy(m, I->random, 32);
    memcpy(m + 32, I->root_pub, 65);
    for (int i = 0; i < 8; i++) { m[97 + i] = (uint8_t)(I->fabric_id >> (8 * i)); m[105 + i] = (uint8_t)(I->peer_node >> (8 * i)); }
    if (mt_crypto_hmac_sha256(mt_span_of(I->ipk, 16), mt_span_of(m, sizeof m), d)) return MT_ERR_CRYPTO;
    mt_tlv_wr_init(&w, mt_buf_of(I->s1, sizeof I->s1));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(I->random, 32));
    mt_tlv_put_u(&w, mt_tlv_ctx(2), sid);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(3), mt_span_of(d, 32));
    mt_tlv_put_bytes(&w, mt_tlv_ctx(4), mt_span_of(I->eph_pub, 65));
    mt_tlv_end(&w);
    if (mt_tlv_wr_done(&w, &s)) return MT_ERR_INVALID;
    I->s1_len = s.len;
    return MT_OK;
}

/* Sigma2: ECDH, S2K, TBEData2, the responder's chain against Root01 and its signature over TBSData2. */
static bool sigma2(ini *I, mt_rng *rng, mt_span s2)
{
    mt_tlv_rd r;
    mt_span random = { 0 }, eph = { 0 }, enc = { 0 }, noc = { 0 }, icac = { 0 }, sig = { 0 };
    uint64_t sid = 0;
    uint8_t h1[32], salt[16 + 32 + 65 + 32], s2k[16], tbe[1000], tbs[1000];
    size_t len;
    if (s2.len > sizeof I->s2) return false;
    memcpy(I->s2, s2.p, s2.len);
    I->s2_len = s2.len;
    mt_tlv_rd_init(&r, mt_span_of(I->s2, I->s2_len));
    if (mt_tlv_next(&r) || mt_tlv_enter(&r)) return false;
    while (!mt_tlv_next(&r)) {
        if (mt_tlv_is_ctx(&r, 1)) mt_tlv_get_bytes(&r, &random);
        else if (mt_tlv_is_ctx(&r, 2)) mt_tlv_get_u64(&r, &sid);
        else if (mt_tlv_is_ctx(&r, 3)) mt_tlv_get_bytes(&r, &eph);
        else if (mt_tlv_is_ctx(&r, 4)) mt_tlv_get_bytes(&r, &enc);
    }
    if (random.len != 32 || eph.len != 65 || enc.len <= 16 || sid == 0 || sid > 0xFFFF) return false;
    I->peer_sid = (uint16_t)sid;
    memcpy(I->peer_eph, eph.p, 65);
    if (mt_crypto_p256_ecdh(rng, I->eph_priv, I->peer_eph, I->shared)) return false;
    mt_crypto_sha256(mt_span_of(I->s1, I->s1_len), h1);
    memcpy(salt, I->ipk, 16);
    memcpy(salt + 16, random.p, 32);
    memcpy(salt + 48, eph.p, 65);
    memcpy(salt + 113, h1, 32);
    if (hkdf(salt, sizeof salt, I->shared, "Sigma2", s2k, 16)) return false;
    static const uint8_t n2[13] = { 'N', 'C', 'A', 'S', 'E', '_', 'S', 'i', 'g', 'm', 'a', '2', 'N' };
    if (mt_crypto_ccm_decrypt(s2k, n2, mt_span_of(NULL, 0), enc, mt_buf_of(tbe, sizeof tbe), &len)) return false;
    mt_tlv_rd_init(&r, mt_span_of(tbe, len));
    if (mt_tlv_next(&r) || mt_tlv_enter(&r)) return false;
    while (!mt_tlv_next(&r)) {
        if (mt_tlv_is_ctx(&r, 1)) mt_tlv_get_bytes(&r, &noc);
        else if (mt_tlv_is_ctx(&r, 2)) mt_tlv_get_bytes(&r, &icac);
        else if (mt_tlv_is_ctx(&r, 3)) mt_tlv_get_bytes(&r, &sig);
    }
    if (!noc.len || sig.len != 64) return false;
    mt_cert cn, ci, cr;
    uint8_t cs[MT_CERT_SCRATCH];
    if (mt_cert_decode(noc, &cn) || (icac.len && mt_cert_decode(icac, &ci)) || mt_cert_decode(ci_root01(), &cr)) return false;
    if (mt_cert_verify_chain(&cn, icac.len ? &ci : NULL, &cr, 0, mt_buf_of(cs, sizeof cs))) return false;
    if (cn.subject.node_id != I->peer_node || cn.subject.fabric_id != I->fabric_id) return false;
    mt_tlv_wr w;
    mt_span t;
    mt_tlv_wr_init(&w, mt_buf_of(tbs, sizeof tbs));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), noc);
    if (icac.len) mt_tlv_put_bytes(&w, mt_tlv_ctx(2), icac);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(3), eph);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(4), mt_span_of(I->eph_pub, 65));
    mt_tlv_end(&w);
    if (mt_tlv_wr_done(&w, &t)) return false;
    return mt_crypto_p256_verify(cn.pubkey.p, t, sig.p) == MT_OK;
}

/* Sigma3 = { 1 TBEData3 encrypted with S3K }, TBEData3 = { 1 NOC, 2 ICAC, 3 signature over TBSData3 } */
static mt_err sigma3(ini *I, mt_rng *rng)
{
    mt_span noc = mt_span_of(v_Node01_01_tlv, sizeof v_Node01_01_tlv), icac = mt_span_of(v_ICA01_tlv, sizeof v_ICA01_tlv);
    uint8_t sig[64], h12[32], salt[48], s3k[16], tbx[1000], enc[1000];
    size_t enc_len = 0;
    mt_tlv_wr w;
    mt_span t;
    mt_sha256 h;
    mt_tlv_wr_init(&w, mt_buf_of(tbx, sizeof tbx));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), noc);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(2), icac);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(3), mt_span_of(I->eph_pub, 65));
    mt_tlv_put_bytes(&w, mt_tlv_ctx(4), mt_span_of(I->peer_eph, 65));
    mt_tlv_end(&w);
    if (mt_tlv_wr_done(&w, &t) || mt_crypto_p256_sign(rng, k_Node01_01_priv, t, sig)) return MT_ERR_CRYPTO;
    mt_tlv_wr_init(&w, mt_buf_of(tbx, sizeof tbx));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), noc);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(2), icac);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(3), mt_span_of(sig, 64));
    mt_tlv_end(&w);
    if (mt_tlv_wr_done(&w, &t)) return MT_ERR_INVALID;
    mt_sha256_begin(&h);
    mt_sha256_update(&h, mt_span_of(I->s1, I->s1_len));
    mt_sha256_update(&h, mt_span_of(I->s2, I->s2_len));
    mt_sha256_finish(&h, h12);
    memcpy(salt, I->ipk, 16);
    memcpy(salt + 16, h12, 32);
    if (hkdf(salt, sizeof salt, I->shared, "Sigma3", s3k, 16)) return MT_ERR_CRYPTO;
    static const uint8_t n3[13] = { 'N', 'C', 'A', 'S', 'E', '_', 'S', 'i', 'g', 'm', 'a', '3', 'N' };
    if (mt_crypto_ccm_encrypt(s3k, n3, mt_span_of(NULL, 0), t, mt_buf_of(enc, sizeof enc), &enc_len)) return MT_ERR_CRYPTO;
    mt_tlv_wr_init(&w, mt_buf_of(I->s3, sizeof I->s3));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(enc, enc_len));
    mt_tlv_end(&w);
    if (mt_tlv_wr_done(&w, &t)) return MT_ERR_INVALID;
    I->s3_len = t.len;
    return MT_OK;
}

static void note_status(ti *t, const ti_msg *m)
{
    t->status_general = m->payload.len >= 2 ? (uint16_t)(m->payload.p[0] | m->payload.p[1] << 8) : 0xFFFF;
    t->status_code = m->payload.len >= 8 ? (uint16_t)(m->payload.p[6] | m->payload.p[7] << 8) : 0xFFFF;
}

mt_err ci_case(ti *t, const mt_fabric *target)
{
    static ini I;   /* large; the test is single-threaded */
    uint16_t xid = t->next_xid++, sid;
    uint8_t okm[48], salt[48], r4[4];
    ti_msg m;
    mt_sha256 h;
    mt_err e;
    memset(&I, 0, sizeof I);
    I.peer_node = target->node_id;
    I.fabric_id = target->fabric_id;
    memcpy(I.ipk, target->ipk, 16);
    memcpy(I.root_pub, target->root_pub, 65);
    do { mt_rng_fill(&t->rng, (uint8_t *)&sid, sizeof sid); } while (sid == 0);
    if ((e = sigma1(&I, &t->rng, sid))) return e;
    if ((e = ti_transact(t, false, xid, 0, OP_SIGMA1, mt_span_of(I.s1, I.s1_len), &m))) return e;
    if (m.opcode == OP_STATUS) { note_status(t, &m); ti_send_ack(t); return MT_ERR_STATE; }
    if (m.opcode != OP_SIGMA2 || !sigma2(&I, &t->rng, m.payload)) return MT_ERR_CRYPTO;
    if ((e = sigma3(&I, &t->rng))) return e;
    if ((e = ti_transact(t, false, xid, 0, OP_SIGMA3, mt_span_of(I.s3, I.s3_len), &m))) return e;
    if (m.opcode != OP_STATUS) return MT_ERR_STATE;
    note_status(t, &m);
    ti_send_ack(t);
    if (t->status_general != 0 || t->status_code != 0) return MT_ERR_STATE;
    /* I2R || R2I || AttestationChallenge = HKDF(shared, IPK || SHA256(Sigma1 || Sigma2 || Sigma3), "SessionKeys") */
    mt_sha256_begin(&h);
    mt_sha256_update(&h, mt_span_of(I.s1, I.s1_len));
    mt_sha256_update(&h, mt_span_of(I.s2, I.s2_len));
    mt_sha256_update(&h, mt_span_of(I.s3, I.s3_len));
    mt_sha256_finish(&h, salt + 16);
    memcpy(salt, I.ipk, 16);
    if ((e = hkdf(salt, sizeof salt, I.shared, "SessionKeys", okm, sizeof okm))) return e;
    memcpy(t->enc, okm, 16);
    memcpy(t->dec, okm + 16, 16);
    mt_wipe(okm, sizeof okm);
    t->local_sid = sid;
    t->peer_sid = I.peer_sid;
    t->sec_src = CI_INITIATOR_NODE;   /* operational node IDs feed the CASE nonce (4.8.1.1) */
    t->sec_peer = I.peer_node;
    mt_rng_fill(&t->rng, r4, sizeof r4);
    mt_msg_tx_init(&t->sec_tx, mt_get_le32(r4), true);
    mt_msg_rx_init(&t->sec_rx);
    t->secure = true;
    return MT_OK;
}
