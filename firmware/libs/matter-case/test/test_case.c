/* Host tests for matter-case.
 *
 * Official data:
 *  - Certificates and their private keys: connectedhomeip src/credentials/tests/CHIPCert_test_vectors.cpp
 *    (matter-cert/test/vectors.h, keys.h here). Fabric FAB000000000001D under Root01 (Node01_01 via ICA01,
 *    Node01_02 directly) and under Root02/ICA02 (Node02_01, Node02_04 with 2 CATs, Node02_08 with 3 CATs).
 *  - The CASE destination-ID example of the spec, as in connectedhomeip TestCASESession.cpp DestinationIdTest.
 *  - The Sigma1 / Sigma3 / TBEData3 parsing cases of connectedhomeip TestCASESession.cpp (Sigma1ParsingTest,
 *    Sigma3ParsingTest, ParseSigma3TBEData), re-encoded here with the same field sizes.
 * Not official (no CASE transcript vectors exist): the full handshakes run against an initiator test double
 * written in this file from the spec text (its own TLV layouts, salts and key schedule, not the lib's), and a
 * known-answer check of the key schedule: kat.py recomputes S2K, S3K and the session keys with stdlib Python
 * (its own P-256 ECDH, HKDF, SHA-256) from the raw Sigma1/2/3 bytes of a deterministic run (`--dump`). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "case_internal.h"
#include "keys.h"
#include "kat_vectors.h"
#include "mt_case.h"
#include "mt_tlv.h"
#include "vectors.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

/* ---- kv fake: staged writes become visible on finish(apply) ---- */

#define KV_N 24
#define KV_CAP 512
typedef struct { uint16_t key, len; bool used; uint8_t d[KV_CAP]; } ent;
static ent applied[KV_N], staged[KV_N];
static bool dirty;

static ent *kfind(ent *a, uint16_t key)
{
    for (int i = 0; i < KV_N; i++) if (a[i].used && a[i].key == key) return &a[i];
    return NULL;
}
static void touch(void) { if (!dirty) { memcpy(staged, applied, sizeof applied); dirty = true; } }
static mt_err f_get(void *c, uint16_t key, mt_buf out, size_t *len)
{
    (void)c;
    ent *e = kfind(applied, key);
    if (!e) return MT_ERR_NOT_FOUND;
    if (e->len > out.cap) return MT_ERR_BUFFER_TOO_SMALL;
    memcpy(out.p, e->d, e->len);
    *len = e->len;
    return MT_OK;
}
static mt_err f_set(void *c, uint16_t key, mt_span v)
{
    (void)c;
    if (v.len > KV_CAP) return MT_ERR_IO;
    touch();
    ent *e = kfind(staged, key);
    for (int i = 0; !e && i < KV_N; i++) if (!staged[i].used) e = &staged[i];
    if (!e) return MT_ERR_IO;
    e->used = true; e->key = key; e->len = (uint16_t)v.len;
    memcpy(e->d, v.p, v.len);
    return MT_OK;
}
static mt_err f_del(void *c, uint16_t key)
{
    (void)c;
    touch();
    ent *e = kfind(staged, key);
    if (e) e->used = false;
    return MT_OK;
}
static mt_err f_finish(void *c, bool apply)
{
    (void)c;
    if (apply && dirty) memcpy(applied, staged, sizeof applied);
    dirty = false;
    return MT_OK;
}
static const mt_kv_ops KV = { NULL, f_get, f_set, f_del, f_finish };

/* ---- fixtures ---- */

#define NVECS (sizeof VECS / sizeof VECS[0])
static const struct vec *vec(const char *name)
{
    for (size_t i = 0; i < NVECS; i++) if (!strcmp(VECS[i].name, name)) return &VECS[i];
    printf("no vector %s\n", name);
    exit(2);
}
static mt_span tl(const char *name) { const struct vec *v = vec(name); return mt_span_of(v->tlv, v->tlv_len); }
static mt_span tl_opt(const char *name) { return name ? tl(name) : mt_span_of(NULL, 0); }

typedef struct { const char *root, *icac, *noc; const uint8_t *priv; uint64_t node_id; } ident;
static const ident R01_N02 = { "Root01", NULL, "Node01_02", k_Node01_02_priv, 0xDEDEDEDE00010002ull };
static const ident R01_I01_N01 = { "Root01", "ICA01", "Node01_01", k_Node01_01_priv, 0xDEDEDEDE00010001ull };
static const ident R02_I02_N01 = { "Root02", "ICA02", "Node02_01", k_Node02_01_priv, 0xDEDEDEDE00020001ull };
static const ident R02_I02_N04 = { "Root02", "ICA02", "Node02_04", k_Node02_04_priv, 0xDEDEDEDE00020004ull };
static const ident R02_I02_N08 = { "Root02", "ICA02", "Node02_08", k_Node02_08_priv, 0xDEDEDEDE00020008ull };
#define FABRIC_ID 0xFAB000000000001Dull
#define NOW 700000000u /* 2022, inside every test certificate's validity */
static const uint8_t EPOCH[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

static mt_fabric_table T;
static uint8_t fscratch[MT_FABRIC_SCRATCH];

/* The device's fabric (pending, or committed through the kv fake). */
static const mt_fabric *device_fabric(const ident *id, bool commit)
{
    uint8_t idx = 0;
    memset(applied, 0, sizeof applied);
    dirty = false;
    mt_fabric_init(&T, &KV);
    CHECK(mt_fabric_stage_key(&T, id->priv, vec(id->noc)->pub) == MT_OK);
    CHECK(mt_fabric_stage_rcac(&T, tl(id->root)) == MT_OK);
    CHECK(mt_fabric_add_noc(&T, tl(id->noc), tl_opt(id->icac), EPOCH, 0x112233ull, 0xFFF1, NOW,
                            mt_buf_of(fscratch, sizeof fscratch), &idx) == MT_OK);
    if (commit) CHECK(mt_fabric_commit(&T, mt_buf_of(fscratch, sizeof fscratch)) == MT_OK);
    const mt_fabric *f = mt_fabric_get(&T, idx);
    CHECK(f && f->pending == !commit && f->node_id == id->node_id);
    return f;
}

static int counter_entropy(void *ctx, uint8_t *out, size_t len)
{
    uint8_t *ctr = ctx;
    for (size_t i = 0; i < len; i++) out[i] = (*ctr)++;
    return 0;
}

static void put_hex(const char *name, const uint8_t *p, size_t n)
{
    printf("%s ", name);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

/* ---- initiator test double (spec 4.14.2, written independently of the lib's internals) ---- */

typedef struct {
    const ident *me;                 /* our credentials */
    const char *peer_root;           /* the responder's root as we know it */
    uint64_t peer_node, fabric_id;
    uint8_t ipk[16], root_pub[65];
    uint8_t ent;
    mt_rng rng;
    uint8_t eph_priv[32], eph_pub[65], random[32];
    uint8_t s1[400], s2[1300], s3[1100];
    size_t s1_len, s2_len, s3_len;
    uint8_t peer_eph[65], shared[32], s2k[16], s3k[16], keys[48], rid[16];
    uint16_t peer_sid;
    mt_sc_peer_params peer_params;
    bool peer_has_icac;
} ini;

static void ini_init(ini *I, const ident *me, const mt_fabric *target, const char *peer_root, uint8_t seed)
{
    memset(I, 0, sizeof *I);
    I->me = me;
    I->peer_root = peer_root;
    I->peer_node = target->node_id;
    I->fabric_id = target->fabric_id;
    memcpy(I->ipk, target->ipk, 16);
    memcpy(I->root_pub, target->root_pub, 65);
    I->ent = seed;
    CHECK(mt_rng_init(&I->rng, counter_entropy, &I->ent) == MT_OK);
}

static void ini_free(ini *I) { mt_rng_free(&I->rng); }

/* HMAC-SHA256(IPK, initiatorRandom || rootPublicKey || fabricId (LE64) || nodeId (LE64)). */
static void dest_id(const uint8_t ipk[16], const uint8_t random[32], const uint8_t root[65], uint64_t fid, uint64_t nid,
                    uint8_t out[32])
{
    uint8_t m[32 + 65 + 16];
    memcpy(m, random, 32);
    memcpy(m + 32, root, 65);
    for (int i = 0; i < 8; i++) { m[97 + i] = (uint8_t)(fid >> (8 * i)); m[105 + i] = (uint8_t)(nid >> (8 * i)); }
    CHECK(mt_crypto_hmac_sha256(mt_span_of(ipk, 16), mt_span_of(m, sizeof m), out) == MT_OK);
}

static void hkdf(const uint8_t *salt, size_t salt_len, const uint8_t ikm[32], const char *info, uint8_t *out, size_t n)
{
    CHECK(mt_crypto_hkdf_sha256(mt_span_of(salt, salt_len), mt_span_of(ikm, 32), mt_span_of(info, strlen(info)),
                                mt_buf_of(out, n)) == MT_OK);
}

typedef struct {
    bool params, resumption, bad_dest, bad_eph;
} s1_opts;

static void ini_sigma1(ini *I, s1_opts o)
{
    uint8_t d[32];
    mt_tlv_wr w;
    mt_span s;
    CHECK(mt_crypto_p256_keygen(&I->rng, I->eph_priv, I->eph_pub) == MT_OK);
    CHECK(mt_rng_fill(&I->rng, I->random, 32) == MT_OK);
    dest_id(I->ipk, I->random, I->root_pub, I->fabric_id, I->peer_node, d);
    if (o.bad_dest) d[5] ^= 1;
    uint8_t eph[65];
    memcpy(eph, I->eph_pub, 65);
    if (o.bad_eph) eph[40] ^= 1;
    mt_tlv_wr_init(&w, mt_buf_of(I->s1, sizeof I->s1));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(I->random, 32));
    mt_tlv_put_u(&w, mt_tlv_ctx(2), 0x1234);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(3), mt_span_of(d, 32));
    mt_tlv_put_bytes(&w, mt_tlv_ctx(4), mt_span_of(eph, 65));
    if (o.params) {
        mt_tlv_start(&w, mt_tlv_ctx(5), MT_TLV_STRUCT);
        mt_tlv_put_u(&w, mt_tlv_ctx(1), 5000);
        mt_tlv_put_u(&w, mt_tlv_ctx(2), 300);
        mt_tlv_put_u(&w, mt_tlv_ctx(3), 4000);
        mt_tlv_put_u(&w, mt_tlv_ctx(4), 17);   /* data model revision: skipped */
        mt_tlv_end(&w);
    }
    if (o.resumption) {
        uint8_t rid[16], mic[16];
        memset(rid, 0xaa, 16);
        memset(mic, 0xbb, 16);
        mt_tlv_put_bytes(&w, mt_tlv_ctx(6), mt_span_of(rid, 16));
        mt_tlv_put_bytes(&w, mt_tlv_ctx(7), mt_span_of(mic, 16));
    }
    mt_tlv_end(&w);
    CHECK(mt_tlv_wr_done(&w, &s) == MT_OK);
    I->s1_len = s.len;
}

/* Process Sigma2: ECDH, S2K, decrypt TBEData2, verify the responder's chain (against the root we know) and
 * signature. Returns false on any problem. */
static bool ini_sigma2(ini *I, mt_span s2)
{
    mt_tlv_rd r;
    mt_span random = { 0 }, eph = { 0 }, enc = { 0 }, noc = { 0 }, icac = { 0 }, sig = { 0 }, rid = { 0 };
    uint64_t sid = 0;
    uint8_t h1[32], salt[16 + 32 + 65 + 32], tbe[1100], tbs[1100];
    size_t len;
    if (s2.len > sizeof I->s2) return false;
    memcpy(I->s2, s2.p, s2.len);
    I->s2_len = s2.len;
    mt_tlv_rd_init(&r, s2);
    if (mt_tlv_next(&r) || mt_tlv_enter(&r)) return false;
    while (!mt_tlv_next(&r)) {
        if (mt_tlv_is_ctx(&r, 1)) mt_tlv_get_bytes(&r, &random);
        else if (mt_tlv_is_ctx(&r, 2)) mt_tlv_get_u64(&r, &sid);
        else if (mt_tlv_is_ctx(&r, 3)) mt_tlv_get_bytes(&r, &eph);
        else if (mt_tlv_is_ctx(&r, 4)) mt_tlv_get_bytes(&r, &enc);
        else if (mt_tlv_is_ctx(&r, 5)) {
            mt_tlv_enter(&r);
            while (!mt_tlv_next(&r)) {
                uint64_t v = 0;
                mt_tlv_get_u64(&r, &v);
                if (mt_tlv_is_ctx(&r, 1)) I->peer_params.idle_ms = (uint32_t)v;
                if (mt_tlv_is_ctx(&r, 2)) I->peer_params.active_ms = (uint32_t)v;
                if (mt_tlv_is_ctx(&r, 3)) I->peer_params.active_threshold_ms = (uint16_t)v;
            }
            mt_tlv_exit(&r);
        }
    }
    if (random.len != 32 || eph.len != 65 || enc.len <= 16 || sid > 0xFFFF) return false;
    I->peer_sid = (uint16_t)sid;
    memcpy(I->peer_eph, eph.p, 65);
    if (mt_crypto_p256_ecdh(&I->rng, I->eph_priv, I->peer_eph, I->shared)) return false;
    mt_crypto_sha256(mt_span_of(I->s1, I->s1_len), h1);
    memcpy(salt, I->ipk, 16);
    memcpy(salt + 16, random.p, 32);
    memcpy(salt + 48, eph.p, 65);
    memcpy(salt + 113, h1, 32);
    hkdf(salt, sizeof salt, I->shared, "Sigma2", I->s2k, 16);
    static const uint8_t n2[13] = { 'N', 'C', 'A', 'S', 'E', '_', 'S', 'i', 'g', 'm', 'a', '2', 'N' };
    if (mt_crypto_ccm_decrypt(I->s2k, n2, mt_span_of(NULL, 0), enc, mt_buf_of(tbe, sizeof tbe), &len)) return false;
    mt_tlv_rd_init(&r, mt_span_of(tbe, len));
    if (mt_tlv_next(&r) || mt_tlv_enter(&r)) return false;
    while (!mt_tlv_next(&r)) {
        if (mt_tlv_is_ctx(&r, 1)) mt_tlv_get_bytes(&r, &noc);
        else if (mt_tlv_is_ctx(&r, 2)) mt_tlv_get_bytes(&r, &icac);
        else if (mt_tlv_is_ctx(&r, 3)) mt_tlv_get_bytes(&r, &sig);
        else if (mt_tlv_is_ctx(&r, 4)) mt_tlv_get_bytes(&r, &rid);
    }
    if (!noc.len || sig.len != 64 || rid.len != 16) return false;
    memcpy(I->rid, rid.p, 16);
    I->peer_has_icac = icac.len != 0;

    /* responder chain against the root we trust, and its node ID */
    mt_cert cn, ci, cr;
    uint8_t cs[MT_CERT_SCRATCH];
    if (mt_cert_decode(noc, &cn) || (icac.len && mt_cert_decode(icac, &ci)) || mt_cert_decode(tl(I->peer_root), &cr)) return false;
    if (mt_cert_verify_chain(&cn, icac.len ? &ci : NULL, &cr, NOW, mt_buf_of(cs, sizeof cs))) return false;
    if (cn.subject.node_id != I->peer_node || cn.subject.fabric_id != I->fabric_id) return false;

    /* TBSData2 = { 1 responderNOC, 2 responderICAC?, 3 responderEphPubKey, 4 initiatorEphPubKey } */
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

typedef struct {
    const ident *certs;      /* send these certificates instead of ours */
    const uint8_t *sign_key; /* sign TBSData3 with this key instead of ours */
    bool tamper;             /* flip a ciphertext bit */
} s3_opts;

static void ini_sigma3(ini *I, s3_opts o)
{
    const ident *c = o.certs ? o.certs : I->me;
    uint8_t sig[64], h12[32], salt[48], tbx[1100], enc[1100];
    size_t enc_len = 0;
    mt_tlv_wr w;
    mt_span t;
    /* TBSData3 = { 1 initiatorNOC, 2 initiatorICAC?, 3 initiatorEphPubKey, 4 responderEphPubKey } */
    mt_tlv_wr_init(&w, mt_buf_of(tbx, sizeof tbx));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), tl(c->noc));
    if (c->icac) mt_tlv_put_bytes(&w, mt_tlv_ctx(2), tl(c->icac));
    mt_tlv_put_bytes(&w, mt_tlv_ctx(3), mt_span_of(I->eph_pub, 65));
    mt_tlv_put_bytes(&w, mt_tlv_ctx(4), mt_span_of(I->peer_eph, 65));
    mt_tlv_end(&w);
    CHECK(mt_tlv_wr_done(&w, &t) == MT_OK);
    CHECK(mt_crypto_p256_sign(&I->rng, o.sign_key ? o.sign_key : c->priv, t, sig) == MT_OK);
    /* TBEData3 = { 1 initiatorNOC, 2 initiatorICAC?, 3 signature } */
    mt_tlv_wr_init(&w, mt_buf_of(tbx, sizeof tbx));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), tl(c->noc));
    if (c->icac) mt_tlv_put_bytes(&w, mt_tlv_ctx(2), tl(c->icac));
    mt_tlv_put_bytes(&w, mt_tlv_ctx(3), mt_span_of(sig, 64));
    mt_tlv_end(&w);
    CHECK(mt_tlv_wr_done(&w, &t) == MT_OK);
    /* S3K: salt = IPK || SHA256(Sigma1 || Sigma2) */
    mt_sha256 h;
    mt_sha256_begin(&h);
    mt_sha256_update(&h, mt_span_of(I->s1, I->s1_len));
    mt_sha256_update(&h, mt_span_of(I->s2, I->s2_len));
    mt_sha256_finish(&h, h12);
    memcpy(salt, I->ipk, 16);
    memcpy(salt + 16, h12, 32);
    hkdf(salt, sizeof salt, I->shared, "Sigma3", I->s3k, 16);
    static const uint8_t n3[13] = { 'N', 'C', 'A', 'S', 'E', '_', 'S', 'i', 'g', 'm', 'a', '3', 'N' };
    CHECK(mt_crypto_ccm_encrypt(I->s3k, n3, mt_span_of(NULL, 0), t, mt_buf_of(enc, sizeof enc), &enc_len) == MT_OK);
    if (o.tamper) enc[enc_len / 2] ^= 0x10;
    mt_tlv_wr_init(&w, mt_buf_of(I->s3, sizeof I->s3));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(enc, enc_len));
    mt_tlv_end(&w);
    CHECK(mt_tlv_wr_done(&w, &t) == MT_OK);
    I->s3_len = t.len;
}

/* I2R || R2I || AttestationChallenge = HKDF(shared, IPK || SHA256(Sigma1 || Sigma2 || Sigma3), "SessionKeys") */
static void ini_keys(ini *I)
{
    uint8_t salt[48];
    mt_sha256 h;
    mt_sha256_begin(&h);
    mt_sha256_update(&h, mt_span_of(I->s1, I->s1_len));
    mt_sha256_update(&h, mt_span_of(I->s2, I->s2_len));
    mt_sha256_update(&h, mt_span_of(I->s3, I->s3_len));
    mt_sha256_finish(&h, salt + 16);
    memcpy(salt, I->ipk, 16);
    hkdf(salt, sizeof salt, I->shared, "SessionKeys", I->keys, 48);
}

/* ---- the device side ---- */

static uint8_t out_mem[1300], work_mem[MT_CASE_WORK];
static mt_buf OUT(void) { return mt_buf_of(out_mem, sizeof out_mem); }
static mt_buf WORK(void) { return mt_buf_of(work_mem, sizeof work_mem); }

typedef struct {
    mt_case_config cfg;
    mt_rng rng;
    uint8_t ent;
    mt_case c;
} dev;

static void dev_init(dev *d, uint8_t seed, uint32_t now, bool params)
{
    memset(d, 0, sizeof *d);
    d->cfg.fabrics = &T;
    if (params) {
        d->cfg.params.idle_ms = 500;
        d->cfg.params.active_ms = 300;
        d->cfg.params.active_threshold_ms = 4000;
        d->cfg.params.specification_version = 0x01030000;
        d->cfg.params.max_paths_per_invoke = 1;
    }
    d->ent = seed;
    CHECK(mt_rng_init(&d->rng, counter_entropy, &d->ent) == MT_OK);
    mt_case_init(&d->c, &d->cfg, &d->rng, 0x4321, now);
}

static void dev_free(dev *d) { mt_case_reset(&d->c); mt_rng_free(&d->rng); }

static bool is_status(const mt_case_reply *rep, uint16_t general, uint16_t code)
{
    return rep->opcode == MT_CASE_OP_STATUS && rep->len == 8 && mt_get_le16(out_mem) == general &&
           mt_get_le32(out_mem + 2) == 0 && mt_get_le16(out_mem + 6) == code;
}

/* Full handshake; returns the result of Sigma3 processing (the Sigma1 step must succeed). */
static mt_err handshake(dev *d, ini *I, s1_opts o1, s3_opts o3, mt_case_reply *rep)
{
    ini_sigma1(I, o1);
    mt_err e = mt_case_recv(&d->c, MT_CASE_OP_SIGMA1, mt_span_of(I->s1, I->s1_len), OUT(), WORK(), rep);
    CHECK(e == MT_OK && rep->opcode == MT_CASE_OP_SIGMA2 && d->c.state == MT_CASE_WAIT_SIGMA3);
    if (e) return e;
    CHECK(ini_sigma2(I, mt_span_of(out_mem, rep->len)));
    ini_sigma3(I, o3);
    return mt_case_recv(&d->c, MT_CASE_OP_SIGMA3, mt_span_of(I->s3, I->s3_len), OUT(), WORK(), rep);
}

/* Both sides agree on the keys and on who the peer is. */
static void check_established(dev *d, ini *I, const mt_fabric *f, const ident *peer, mt_err e, const mt_case_reply *rep)
{
    mt_case_session s;
    CHECK(e == MT_OK && is_status(rep, 0, 0) && d->c.state == MT_CASE_ESTABLISHED);
    ini_keys(I);
    CHECK(mt_case_session_keys(&d->c, &s) == MT_OK);
    CHECK(!memcmp(s.i2r, I->keys, 16) && !memcmp(s.r2i, I->keys + 16, 16) && !memcmp(s.attestation_challenge, I->keys + 32, 16));
    CHECK(s.local_session_id == 0x4321 && s.peer_session_id == 0x1234 && I->peer_sid == 0x4321);
    CHECK(s.fabric_index == f->index && s.local_node_id == f->node_id && s.peer_node_id == peer->node_id);
}

static void run_ok(const ident *device, bool commit, const ident *peer, bool params)
{
    dev d;
    ini I;
    mt_case_reply rep;
    const mt_fabric *f = device_fabric(device, commit);
    dev_init(&d, 1, NOW, params);
    ini_init(&I, peer, f, device->root, 101);
    s1_opts o1 = { .params = params };
    mt_err e = handshake(&d, &I, o1, (s3_opts){ 0 }, &rep);
    check_established(&d, &I, f, peer, e, &rep);
    CHECK(I.peer_has_icac == (device->icac != NULL));
    mt_case_session s;
    mt_case_session_keys(&d.c, &s);
    if (params) {
        CHECK(s.peer.idle_ms == 5000 && s.peer.active_ms == 300 && s.peer.active_threshold_ms == 4000);
        CHECK(I.peer_params.idle_ms == 500 && I.peer_params.active_ms == 300 && I.peer_params.active_threshold_ms == 4000);
    } else {
        CHECK(s.peer.idle_ms == 0 && s.peer.active_ms == 0 && I.peer_params.idle_ms == 0);
    }
    /* finished: more input changes nothing */
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA3, mt_span_of(I.s3, I.s3_len), OUT(), WORK(), &rep) == MT_ERR_STATE &&
          rep.len == 0 && d.c.state == MT_CASE_ESTABLISHED);
    dev_free(&d);
    ini_free(&I);
}

static void test_round_trips(void)
{
    run_ok(&R01_N02, false, &R01_I01_N01, false);   /* pending fabric, no ICAC (Apple's shape); peer via ICAC */
    run_ok(&R01_N02, true, &R01_I01_N01, true);     /* committed, with session parameters both ways */
    run_ok(&R01_I01_N01, false, &R01_N02, true);    /* device with ICAC (chip-tool's shape) */
    run_ok(&R01_I01_N01, true, &R01_N02, false);
    run_ok(&R02_I02_N01, true, &R02_I02_N04, false);

    /* CATs of the peer: Node02_04 has 2, Node02_08 has 3 */
    static const struct { const ident *peer; uint8_t n; uint32_t cats[3]; } cat[] = {
        { &R02_I02_N04, 2, { 0xABCE1002, 0xABCD0003 } },
        { &R02_I02_N08, 3, { 0xABCF00A0, 0xABCD0020, 0xABCE0100 } },
    };
    for (size_t k = 0; k < 2; k++) {
        dev d;
        ini I;
        mt_case_reply rep;
        mt_case_session s;
        const mt_fabric *f = device_fabric(&R02_I02_N01, false);
        dev_init(&d, 2, NOW, false);
        ini_init(&I, cat[k].peer, f, "Root02", 102);
        mt_err e = handshake(&d, &I, (s1_opts){ 0 }, (s3_opts){ 0 }, &rep);
        check_established(&d, &I, f, cat[k].peer, e, &rep);
        CHECK(mt_case_session_keys(&d.c, &s) == MT_OK && s.n_peer_cats == cat[k].n);
        for (unsigned i = 0; i < cat[k].n; i++) {
            bool found = false;
            for (unsigned j = 0; j < s.n_peer_cats; j++) found |= s.peer_cats[j] == cat[k].cats[i];
            CHECK(found);
        }
        dev_free(&d);
        ini_free(&I);
    }

    /* Sigma1 with resumption fields still gets a full Sigma2 */
    {
        dev d;
        ini I;
        mt_case_reply rep;
        const mt_fabric *f = device_fabric(&R01_N02, true);
        dev_init(&d, 3, NOW, false);
        ini_init(&I, &R01_I01_N01, f, "Root01", 103);
        mt_err e = handshake(&d, &I, (s1_opts){ .resumption = true }, (s3_opts){ 0 }, &rep);
        check_established(&d, &I, f, &R01_I01_N01, e, &rep);
        dev_free(&d);
        ini_free(&I);
    }

    /* time unknown (0): validity is not checked */
    {
        dev d;
        ini I;
        mt_case_reply rep;
        const mt_fabric *f = device_fabric(&R01_N02, false);
        dev_init(&d, 4, 0, false);
        ini_init(&I, &R01_I01_N01, f, "Root01", 104);
        mt_err e = handshake(&d, &I, (s1_opts){ 0 }, (s3_opts){ 0 }, &rep);
        check_established(&d, &I, f, &R01_I01_N01, e, &rep);
        dev_free(&d);
        ini_free(&I);
    }
}

/* ---- key schedule known answers (kat.py) ---- */

static void canonical(dev *d, ini *I, mt_case_reply *rep, mt_err *e)
{
    const mt_fabric *f = device_fabric(&R01_N02, false);
    dev_init(d, 7, NOW, true);
    ini_init(I, &R01_I01_N01, f, "Root01", 77);
    *e = handshake(d, I, (s1_opts){ .params = true }, (s3_opts){ 0 }, rep);
}

static void test_kat(void)
{
    dev d;
    ini I;
    mt_case_reply rep;
    mt_err e;
    mt_case_session s;
    canonical(&d, &I, &rep, &e);
    CHECK(e == MT_OK && mt_case_session_keys(&d.c, &s) == MT_OK);
    uint8_t h[32];
    mt_sha256 t;
    mt_sha256_begin(&t);
    mt_sha256_update(&t, mt_span_of(I.s1, I.s1_len));
    mt_sha256_update(&t, mt_span_of(I.s2, I.s2_len));
    mt_sha256_update(&t, mt_span_of(I.s3, I.s3_len));
    mt_sha256_finish(&t, h);
    if (memcmp(h, KAT_TRANSCRIPT, 32)) printf("note: transcript differs from kat_vectors.h; regenerate it as described in kat.py\n");
    CHECK(!memcmp(h, KAT_TRANSCRIPT, 32));
    CHECK(!memcmp(I.s2k, KAT_S2K, 16));
    CHECK(!memcmp(I.s3k, KAT_S3K, 16));
    CHECK(!memcmp(s.i2r, KAT_KEYS, 16) && !memcmp(s.r2i, KAT_KEYS + 16, 16) && !memcmp(s.attestation_challenge, KAT_KEYS + 32, 16));
    dev_free(&d);
    ini_free(&I);
}

static void dump(void)
{
    dev d;
    ini I;
    mt_case_reply rep;
    mt_err e;
    canonical(&d, &I, &rep, &e);
    if (e) { printf("handshake failed %d\n", e); exit(1); }
    put_hex("ini_eph_priv", I.eph_priv, 32);
    put_hex("ipk", I.ipk, 16);
    put_hex("sigma1", I.s1, I.s1_len);
    put_hex("sigma2", I.s2, I.s2_len);
    put_hex("sigma3", I.s3, I.s3_len);
}

/* ---- negative cases ---- */

static void test_bad_destination(void)
{
    dev d;
    ini I;
    mt_case_reply rep;
    const mt_fabric *f = device_fabric(&R01_N02, true);
    dev_init(&d, 5, NOW, false);
    ini_init(&I, &R01_I01_N01, f, "Root01", 105);
    ini_sigma1(&I, (s1_opts){ .bad_dest = true });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_ERR_NOT_FOUND);
    CHECK(is_status(&rep, 1, MT_CASE_CODE_NO_SHARED_ROOT) && d.c.state == MT_CASE_FAILED);
    /* FAILED is final */
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_ERR_STATE && rep.len == 0);
    dev_free(&d);

    /* wrong IPK (another epoch key) */
    dev_init(&d, 5, NOW, false);
    ini_init(&I, &R01_I01_N01, f, "Root01", 105);
    I.ipk[0] ^= 1;
    ini_sigma1(&I, (s1_opts){ 0 });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_ERR_NOT_FOUND);
    dev_free(&d);
    ini_free(&I);

    /* a node ID the device doesn't have */
    dev_init(&d, 5, NOW, false);
    ini_init(&I, &R01_I01_N01, f, "Root01", 105);
    I.peer_node++;
    ini_sigma1(&I, (s1_opts){ 0 });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_ERR_NOT_FOUND);
    dev_free(&d);
    ini_free(&I);

    /* invalid initiator ephemeral key */
    dev_init(&d, 5, NOW, false);
    ini_init(&I, &R01_I01_N01, f, "Root01", 105);
    ini_sigma1(&I, (s1_opts){ .bad_eph = true });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_ERR_CRYPTO);
    CHECK(is_status(&rep, 1, MT_CASE_CODE_INVALID_PARAM));
    dev_free(&d);
    ini_free(&I);
}

/* Sigma3 failures: each one gives INVALID_PARAMETER and FAILED. */
static void sigma3_fails(const ident *device, const ident *peer, s3_opts o3, uint32_t now, mt_err want)
{
    dev d;
    ini I;
    mt_case_reply rep;
    const mt_fabric *f = device_fabric(device, true);
    dev_init(&d, 6, now, false);
    ini_init(&I, peer, f, device->root, 106);
    mt_err e = handshake(&d, &I, (s1_opts){ 0 }, o3, &rep);
    CHECK(e == want);
    CHECK(is_status(&rep, 1, MT_CASE_CODE_INVALID_PARAM) && d.c.state == MT_CASE_FAILED);
    CHECK(mt_case_session_keys(&d.c, &(mt_case_session){ 0 }) == MT_ERR_STATE);
    dev_free(&d);
    ini_free(&I);
}

static void test_sigma3_failures(void)
{
    /* bad signature: TBSData3 signed with another node's key */
    sigma3_fails(&R01_N02, &R01_I01_N01, (s3_opts){ .sign_key = k_Node01_02_priv }, NOW, MT_ERR_CRYPTO);
    /* wrong root: Node02_01 / ICA02 / Root02 has the same fabric ID, correctly signed, but not our root */
    sigma3_fails(&R01_N02, &R01_I01_N01, (s3_opts){ .certs = &R02_I02_N01 }, NOW, MT_ERR_INVALID);
    sigma3_fails(&R01_I01_N01, &R01_N02, (s3_opts){ .certs = &R02_I02_N04 }, NOW, MT_ERR_INVALID);
    /* tampered TBEData3 ciphertext */
    sigma3_fails(&R01_N02, &R01_I01_N01, (s3_opts){ .tamper = true }, NOW, MT_ERR_CRYPTO);
    /* peer certificate outside its validity (after 2040 / before 2020) */
    sigma3_fails(&R01_N02, &R01_I01_N01, (s3_opts){ 0 }, 0x7F000000u, MT_ERR_EXPIRED);
    sigma3_fails(&R01_N02, &R01_I01_N01, (s3_opts){ 0 }, 1000u, MT_ERR_EXPIRED);
}

static void test_fabric_gone(void)
{
    dev d;
    ini I;
    mt_case_reply rep;
    const mt_fabric *f = device_fabric(&R01_N02, false);
    dev_init(&d, 8, NOW, false);
    ini_init(&I, &R01_I01_N01, f, "Root01", 108);
    ini_sigma1(&I, (s1_opts){ 0 });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_OK);
    CHECK(ini_sigma2(&I, mt_span_of(out_mem, rep.len)));
    ini_sigma3(&I, (s3_opts){ 0 });
    mt_fabric_abort(&T); /* fail-safe expired between Sigma2 and Sigma3 */
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA3, mt_span_of(I.s3, I.s3_len), OUT(), WORK(), &rep) == MT_ERR_NOT_FOUND);
    CHECK(is_status(&rep, 1, MT_CASE_CODE_NO_SHARED_ROOT) && d.c.state == MT_CASE_FAILED);
    dev_free(&d);
    ini_free(&I);

    /* committed while the handshake runs: still the same fabric */
    f = device_fabric(&R01_N02, false);
    dev_init(&d, 8, NOW, false);
    ini_init(&I, &R01_I01_N01, f, "Root01", 108);
    ini_sigma1(&I, (s1_opts){ 0 });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_OK);
    CHECK(ini_sigma2(&I, mt_span_of(out_mem, rep.len)));
    ini_sigma3(&I, (s3_opts){ 0 });
    CHECK(mt_fabric_commit(&T, mt_buf_of(fscratch, sizeof fscratch)) == MT_OK);
    mt_err e = mt_case_recv(&d.c, MT_CASE_OP_SIGMA3, mt_span_of(I.s3, I.s3_len), OUT(), WORK(), &rep);
    check_established(&d, &I, mt_fabric_get(&T, d.c.fabric_index), &R01_I01_N01, e, &rep);
    dev_free(&d);
    ini_free(&I);

    /* removed */
    f = device_fabric(&R01_N02, true);
    dev_init(&d, 8, NOW, false);
    ini_init(&I, &R01_I01_N01, f, "Root01", 108);
    ini_sigma1(&I, (s1_opts){ 0 });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_OK);
    CHECK(ini_sigma2(&I, mt_span_of(out_mem, rep.len)));
    ini_sigma3(&I, (s3_opts){ 0 });
    CHECK(mt_fabric_remove(&T, d.c.fabric_index) == MT_OK);
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA3, mt_span_of(I.s3, I.s3_len), OUT(), WORK(), &rep) == MT_ERR_NOT_FOUND);
    dev_free(&d);
    ini_free(&I);
}

static void test_protocol(void)
{
    dev d;
    ini I;
    mt_case_reply rep;
    const mt_fabric *f = device_fabric(&R01_N02, true);

    /* Sigma3 before Sigma1 */
    dev_init(&d, 9, NOW, false);
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA3, mt_span_of("\x15\x18", 2), OUT(), WORK(), &rep) == MT_ERR_STATE);
    CHECK(is_status(&rep, 1, MT_CASE_CODE_INVALID_PARAM) && d.c.state == MT_CASE_FAILED);
    dev_free(&d);

    /* the initiator rejects our Sigma2 with a StatusReport: no reply, codes kept */
    dev_init(&d, 9, NOW, false);
    ini_init(&I, &R01_I01_N01, f, "Root01", 109);
    ini_sigma1(&I, (s1_opts){ 0 });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_OK);
    static const uint8_t st[8] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 };
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_STATUS, mt_span_of(st, 8), OUT(), WORK(), &rep) == MT_ERR_STATE);
    CHECK(rep.len == 0 && d.c.state == MT_CASE_FAILED && d.c.peer_general == 1 && d.c.peer_protocol == 0 && d.c.peer_code == 2);
    uint8_t zero[MT_P256_SCALAR_LEN] = { 0 };
    CHECK(!memcmp(d.c.shared, zero, sizeof zero));
    dev_free(&d);
    ini_free(&I);

    /* a second Sigma1 on the same exchange */
    dev_init(&d, 9, NOW, false);
    ini_init(&I, &R01_I01_N01, f, "Root01", 109);
    ini_sigma1(&I, (s1_opts){ 0 });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_OK);
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_ERR_STATE);
    CHECK(is_status(&rep, 1, MT_CASE_CODE_INVALID_PARAM));
    dev_free(&d);
    ini_free(&I);

    /* Sigma2 retransmissions are the xchg layer's job: the reply is built once. Buffers too small: */
    dev_init(&d, 9, NOW, false);
    ini_init(&I, &R01_I01_N01, f, "Root01", 109);
    ini_sigma1(&I, (s1_opts){ 0 });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), mt_buf_of(out_mem, 300), WORK(), &rep) ==
          MT_ERR_BUFFER_TOO_SMALL);
    CHECK(is_status(&rep, 1, MT_CASE_CODE_INVALID_PARAM));
    dev_free(&d);
    dev_init(&d, 9, NOW, false);
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), mt_buf_of(work_mem, 500), &rep) ==
          MT_ERR_BUFFER_TOO_SMALL);
    dev_free(&d);
    dev_init(&d, 9, NOW, false);
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), mt_buf_of(out_mem, 4), WORK(), &rep) ==
          MT_ERR_BUFFER_TOO_SMALL);
    CHECK(rep.len == 0 && rep.opcode == 0);
    dev_free(&d);
    ini_free(&I);

    /* the largest Sigma2 we can produce fits MT_CASE_OUT_MIN: device with ICAC, all parameters */
    f = device_fabric(&R01_I01_N01, true);
    dev_init(&d, 9, NOW, true);
    d.cfg.params.data_model_revision = 17;
    d.cfg.params.im_revision = 11;
    ini_init(&I, &R01_N02, f, "Root01", 109);
    ini_sigma1(&I, (s1_opts){ 0 });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), mt_buf_of(out_mem, MT_CASE_OUT_MIN), WORK(),
                       &rep) == MT_OK);
    CHECK(rep.len + (2 * MT_CASE_CERT_MAX - vec("Node01_01")->tlv_len - vec("ICA01")->tlv_len) + 4 <= MT_CASE_OUT_MIN);
    dev_free(&d);
    ini_free(&I);
}

/* ---- message parsing, after connectedhomeip TestCASESession.cpp ---- */

typedef struct {
    size_t random_len, dest_len, pub_len, rid_len, mic_len;
    uint32_t session_id;
    bool profile_tags, future, no_end;
    bool ok;
} s1_case;

static mt_span enc_sigma1(const s1_case *k, uint8_t *buf, size_t cap)
{
    uint8_t b[80];
    mt_tlv_wr w;
    memset(b, 1, sizeof b);
    mt_tlv_wr_init(&w, mt_buf_of(buf, cap));
#define TAG(n) (k->profile_tags ? mt_tlv_common(n) : mt_tlv_ctx(n))
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, TAG(1), mt_span_of(b, k->random_len));
    mt_tlv_put_u(&w, TAG(2), k->session_id);
    mt_tlv_put_bytes(&w, TAG(3), mt_span_of(b, k->dest_len));
    mt_tlv_put_bytes(&w, TAG(4), mt_span_of(b, k->pub_len));
    if (k->rid_len) mt_tlv_put_bytes(&w, TAG(6), mt_span_of(b, k->rid_len));
    if (k->mic_len) mt_tlv_put_bytes(&w, TAG(7), mt_span_of(b, k->mic_len));
    if (k->future) mt_tlv_put_u(&w, TAG(11), 77);
    if (!k->no_end) mt_tlv_end(&w);
#undef TAG
    return mt_span_of(buf, w.len);
}

static void test_parse_sigma1(void)
{
    const s1_case base = { 32, 32, 65, 0, 0, 0, false, false, false, true };
    s1_case k[20];
    int n = 0;
    k[n++] = base;                                                            /* Sigma1Params */
    k[n] = base; k[n].no_end = true; k[n++].ok = false;                       /* NoStructEnd */
    k[n] = base; k[n].profile_tags = true; k[n++].ok = false;                 /* WrongTags */
    k[n] = base; k[n].random_len = 33; k[n++].ok = false;
    k[n] = base; k[n].random_len = 31; k[n++].ok = false;
    k[n] = base; k[n].dest_len = 33; k[n++].ok = false;
    k[n] = base; k[n].dest_len = 31; k[n++].ok = false;
    k[n] = base; k[n].pub_len = 66; k[n++].ok = false;
    k[n] = base; k[n].pub_len = 64; k[n++].ok = false;
    k[n] = base; k[n].rid_len = 16; k[n++].mic_len = 16;                      /* WithResumption */
    k[n] = base; k[n].rid_len = 17; k[n].mic_len = 16; k[n++].ok = false;
    k[n] = base; k[n].rid_len = 15; k[n].mic_len = 16; k[n++].ok = false;
    k[n] = base; k[n].rid_len = 16; k[n].mic_len = 17; k[n++].ok = false;     /* (upstream's TooLongResumeMIC sets the rid) */
    k[n] = base; k[n].rid_len = 16; k[n].mic_len = 15; k[n++].ok = false;
    k[n] = base; k[n].rid_len = 16; k[n++].ok = false;                        /* ID without MIC */
    k[n] = base; k[n].mic_len = 16; k[n++].ok = false;                        /* MIC without ID */
    k[n] = base; k[n++].session_id = 0xFFFF;                                  /* SessionIdMax */
    k[n] = base; k[n].session_id = 0x10000; k[n++].ok = false;                /* SessionIdTooBig */
    k[n] = base; k[n++].future = true;                                        /* FutureProofTlvElement */
    k[n] = base; k[n].future = true; k[n].no_end = true; k[n++].ok = false;
    for (int i = 0; i < n; i++) {
        uint8_t buf[300];
        case_sigma1 s;
        mt_err e = case_parse_sigma1(enc_sigma1(&k[i], buf, sizeof buf), &s);
        if ((e == MT_OK) != k[i].ok) printf("  sigma1 case %d: %d\n", i, e);
        CHECK((e == MT_OK) == k[i].ok);
        if (k[i].ok) CHECK(s.resumption == (k[i].rid_len != 0) && s.session_id == k[i].session_id);
    }
    /* duplicate field, empty input, not a structure */
    uint8_t buf[300];
    mt_span sp = enc_sigma1(&base, buf, sizeof buf);
    case_sigma1 s;
    buf[sp.len - 1] = 0x24; /* replace the end with a second session ID (u8, ctx 2) ... */
    buf[sp.len] = 0x02;
    buf[sp.len + 1] = 0x05;
    buf[sp.len + 2] = 0x18;
    CHECK(case_parse_sigma1(mt_span_of(buf, sp.len + 3), &s) == MT_ERR_INVALID);
    CHECK(case_parse_sigma1(mt_span_of(buf, 0), &s) == MT_ERR_INVALID);
    CHECK(case_parse_sigma1(mt_span_of("\x16\x18", 2), &s) == MT_ERR_INVALID);
}

static void test_parse_sigma3(void)
{
    uint8_t buf[1300], b[MT_CASE_OUT_MIN + 32];
    mt_tlv_wr w;
    mt_span enc;
    memset(b, 1, sizeof b);
    static const struct { size_t len; bool future, no_end, profile, ok; } k[] = {
        { 17, false, false, false, true },    /* Sigma3Params: MIC + 1 */
        { 17, false, true, false, false },    /* NoStructEnd */
        { 17, false, false, true, false },    /* WrongTags */
        { 16, false, false, false, false },   /* TooShortEncrypted3: only a MIC */
        { 17, true, false, false, true },     /* FutureProofTlvElement (tag 7) */
        { 17, true, true, false, false },
    };
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
        mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
        mt_tlv_put_bytes(&w, k[i].profile ? mt_tlv_common(1) : mt_tlv_ctx(1), mt_span_of(b, k[i].len));
        if (k[i].future) mt_tlv_put_u(&w, mt_tlv_ctx(7), 77);
        if (!k[i].no_end) mt_tlv_end(&w);
        mt_err e = case_parse_sigma3(mt_span_of(buf, w.len), &enc);
        CHECK((e == MT_OK) == k[i].ok);
        if (k[i].ok) CHECK(enc.len == k[i].len);
    }
    /* TooLongEncrypted3: more than the reply buffer can take is refused by the state machine */
    dev d;
    ini I;
    mt_case_reply rep;
    const mt_fabric *f = device_fabric(&R01_N02, true);
    dev_init(&d, 10, NOW, false);
    ini_init(&I, &R01_I01_N01, f, "Root01", 110);
    ini_sigma1(&I, (s1_opts){ 0 });
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA1, mt_span_of(I.s1, I.s1_len), OUT(), WORK(), &rep) == MT_OK);
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(1), mt_span_of(b, MT_CASE_OUT_MIN + 17));
    mt_tlv_end(&w);
    CHECK(mt_case_recv(&d.c, MT_CASE_OP_SIGMA3, mt_span_of(buf, w.len), mt_buf_of(out_mem, MT_CASE_OUT_MIN), WORK(), &rep) ==
          MT_ERR_INVALID);
    CHECK(is_status(&rep, 1, MT_CASE_CODE_INVALID_PARAM));
    dev_free(&d);
    ini_free(&I);
}

static void test_parse_tbe3(void)
{
    static const struct { size_t noc, icac, sig; bool future, no_end, profile, ok; } k[] = {
        { 400, 400, 64, false, false, false, true },    /* Sigma3TBEDataParams */
        { 400, 400, 64, false, true, false, false },    /* NoStructEnd */
        { 400, 400, 64, false, false, true, false },    /* WrongTags */
        { 401, 400, 64, false, false, false, false },   /* TooLongNOC */
        { 400, 401, 64, false, false, false, false },   /* TooLongICAC */
        { 400, 400, 65, false, false, false, false },   /* TooLongSignature */
        { 400, 400, 63, false, false, false, false },   /* TooShortSignature */
        { 400, 400, 64, true, false, false, true },     /* FutureProofTlvElement (tag 11) */
        { 400, 400, 64, true, true, false, false },
        { 400, 0, 64, false, false, false, true },      /* no ICAC */
        { 0, 400, 64, false, false, false, false },     /* no NOC */
    };
    uint8_t buf[1100], noc[401], icac[401], sig[65];
    memset(noc, 1, sizeof noc);
    memset(icac, 2, sizeof icac);
    memset(sig, 3, sizeof sig);
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        mt_tlv_wr w;
        case_tbe3 t;
        mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
        mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
#define TAG(n) (k[i].profile ? mt_tlv_common(n) : mt_tlv_ctx(n))
        if (k[i].noc) mt_tlv_put_bytes(&w, TAG(1), mt_span_of(noc, k[i].noc));
        if (k[i].icac) mt_tlv_put_bytes(&w, TAG(2), mt_span_of(icac, k[i].icac));
        mt_tlv_put_bytes(&w, TAG(3), mt_span_of(sig, k[i].sig));
        if (k[i].future) mt_tlv_put_u(&w, TAG(11), 77);
#undef TAG
        if (!k[i].no_end) mt_tlv_end(&w);
        mt_err e = case_parse_tbe3(mt_span_of(buf, w.len), &t);
        CHECK((e == MT_OK) == k[i].ok);
        if (k[i].ok)
            CHECK(t.noc.len == k[i].noc && t.noc.p[0] == 1 && t.icac.len == k[i].icac && (!t.icac.len || t.icac.p[0] == 2) &&
                  t.sig[0] == 3);
    }
}

/* ---- the spec's destination-ID example (connectedhomeip TestCASESession.cpp DestinationIdTest) ---- */

static void test_destination_id(void)
{
    static const uint8_t root[65] = {
        0x04, 0x4a, 0x9f, 0x42, 0xb1, 0xca, 0x48, 0x40, 0xd3, 0x72, 0x92, 0xbb, 0xc7, 0xf6, 0xa7, 0xe1, 0x1e,
        0x22, 0x20, 0x0c, 0x97, 0x6f, 0xc9, 0x00, 0xdb, 0xc9, 0x8a, 0x7a, 0x38, 0x3a, 0x64, 0x1c, 0xb8, 0x25,
        0x4a, 0x2e, 0x56, 0xd4, 0xe2, 0x95, 0xa8, 0x47, 0x94, 0x3b, 0x4e, 0x38, 0x97, 0xc4, 0xa7, 0x73, 0xe9,
        0x30, 0x27, 0x7b, 0x4d, 0x9f, 0xbe, 0xde, 0x8a, 0x05, 0x26, 0x86, 0xbf, 0xac, 0xfa };
    static const uint8_t ipk[16] = { 0x9b, 0xc6, 0x1c, 0xd9, 0xc6, 0x2a, 0x2d, 0xf6, 0xd6, 0x4d, 0xfc, 0xaa, 0x9d, 0xc4, 0x72, 0xd4 };
    static const uint8_t rnd[32] = { 0x7e, 0x17, 0x12, 0x31, 0x56, 0x8d, 0xfa, 0x17, 0x20, 0x6b, 0x3a, 0xcc, 0xf8, 0xfa, 0xec, 0x2f,
                                     0x4d, 0x21, 0xb5, 0x80, 0x11, 0x31, 0x96, 0xf4, 0x7c, 0x7c, 0x4d, 0xeb, 0x81, 0x0a, 0x73, 0xdc };
    static const uint8_t want[32] = { 0xdc, 0x35, 0xdd, 0x5f, 0xc9, 0x13, 0x4c, 0xc5, 0x54, 0x45, 0x38, 0xc9, 0xc3, 0xfc, 0x42, 0x97,
                                      0xc1, 0xec, 0x33, 0x70, 0xc8, 0x39, 0x13, 0x6a, 0x80, 0xe1, 0x07, 0x96, 0x45, 0x1d, 0x4c, 0x53 };
    uint8_t d[32];
    CHECK(mt_fabric_destination_id(ipk, rnd, root, 0x2906C908D115D362ull, 0xCD5544AA7B13EF14ull, d) == MT_OK && !memcmp(d, want, 32));
    dest_id(ipk, rnd, root, 0x2906C908D115D362ull, 0xCD5544AA7B13EF14ull, d); /* the test double's own */
    CHECK(!memcmp(d, want, 32));
    dest_id(ipk, rnd, root, 0x2906C908D115D362ull, 0xCD5544AA7B13EF15ull, d);
    CHECK(memcmp(d, want, 32));
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--dump")) { dump(); return 0; }
    test_destination_id();
    test_parse_sigma1();
    test_parse_sigma3();
    test_parse_tbe3();
    test_round_trips();
    test_kat();
    test_bad_destination();
    test_sigma3_failures();
    test_fabric_gone();
    test_protocol();
    printf("matter-case: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
