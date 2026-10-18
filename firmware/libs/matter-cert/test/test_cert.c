/* Host tests for matter-cert.
 * Vectors: connectedhomeip src/credentials/tests/CHIPCert_test_vectors.cpp (Apache-2.0), extracted by
 * gen_vectors.py into vectors.h: for every test certificate the Matter-TLV form, the X.509 DER form
 * and the public key. The DER TBSCertificate rebuilt from the TLV must equal the DER's TBS byte for
 * byte, and the DER signature must equal the TLV signature. CSR: checked by `openssl req -verify`
 * (skipped with a message when openssl is missing) and by an independent in-test DER walk.
 * Time conversions: boundary dates computed by hand (2049-12-31 23:59:59 UTC, 2050-01-01, 2000-02-29). */
#define _POSIX_C_SOURCE 200809L /* popen/pclose under -std=c11 (glibc hides them otherwise) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mt_cert.h"
#include "mt_tlv.h"
#include "vectors.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define NVECS (sizeof VECS / sizeof VECS[0])

static int counter_entropy(void *ctx, uint8_t *out, size_t len)
{
    uint8_t *c = ctx;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)((*c)++ * 91 + 7);
    return 0;
}

static const struct vec *vec(const char *name)
{
    for (size_t i = 0; i < NVECS; i++)
        if (!strcmp(VECS[i].name, name)) return &VECS[i];
    printf("no vector %s\n", name);
    exit(2);
}

static mt_cert load(const char *name)
{
    mt_cert c;
    const struct vec *v = vec(name);
    mt_err e = mt_cert_decode(mt_span_of(v->tlv, v->tlv_len), &c);
    if (e) { printf("decode %s failed: %d\n", name, e); exit(2); }
    return c;
}

/* Minimal DER header walk: returns header length, sets *len. */
static size_t der_hdr(const uint8_t *p, size_t *len)
{
    if (p[1] < 0x80) { *len = p[1]; return 2; }
    if (p[1] == 0x81) { *len = p[2]; return 3; }
    *len = (size_t)p[2] << 8 | p[3];
    return 4;
}

/* Splits an X.509 certificate / CSR DER into its three top-level elements (whole TLVs). */
static void der_split3(const uint8_t *der, mt_span out[3])
{
    size_t n, h = der_hdr(der, &n), off = h;
    for (int i = 0; i < 3; i++) {
        size_t hl = der_hdr(der + off, &n);
        out[i] = mt_span_of(der + off, hl + n);
        off += hl + n;
    }
}

static int sig_matches_der(const mt_cert *c, mt_span bitstring)
{
    size_t n, h = der_hdr(bitstring.p, &n);
    uint8_t raw[64];
    return bitstring.p[h] == 0 && mt_crypto_p256_sig_from_der(mt_span_of(bitstring.p + h + 1, n - 1), raw) == MT_OK &&
           memcmp(raw, c->sig.p, 64) == 0;
}

static void test_all_vectors(void)
{
    uint8_t scratch[MT_CERT_SCRATCH];
    for (size_t i = 0; i < NVECS; i++) {
        const struct vec *v = &VECS[i];
        mt_cert c;
        mt_err e = mt_cert_decode(mt_span_of(v->tlv, v->tlv_len), &c);
        if (e) printf("  %s: decode -> %d\n", v->name, e);
        CHECK(e == MT_OK);
        if (e) continue;
        CHECK(c.pubkey.len == 65 && !memcmp(c.pubkey.p, v->pub, 65));

        mt_span parts[3], tbs;
        der_split3(v->der, parts);
        e = mt_cert_build_tbs(&c, mt_buf_of(scratch, sizeof scratch), &tbs);
        if (e || tbs.len != parts[0].len || memcmp(tbs.p, parts[0].p, tbs.len)) printf("  %s: TBS differs (%d)\n", v->name, e);
        CHECK(e == MT_OK && tbs.len == parts[0].len && !memcmp(tbs.p, parts[0].p, tbs.len));
        CHECK(sig_matches_der(&c, parts[2]));
        CHECK(parts[1].len == 12 && !memcmp(parts[1].p + 2, "\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02", 10));
    }
}

static void test_fields(void)
{
    mt_cert c = load("Root01");
    CHECK(c.issuer.has == MT_DN_HAS_RCAC && c.issuer.rcac_id == 0xCACACACA00000001ull);
    CHECK(c.subject.rcac_id == 0xCACACACA00000001ull);
    CHECK(c.has_bc && c.is_ca && c.has_ku && c.key_usage == (MT_KU_KEY_CERT_SIGN | MT_KU_CRL_SIGN));
    CHECK(c.not_before == 656087023u && c.not_after == 1287239022u);
    CHECK(c.serial.len == 8 && c.skid.len == 20 && c.akid.len == 20 && c.n_eku == 0 && c.path_len == -1);

    c = load("Node01_01");
    CHECK(c.subject.node_id == 0xDEDEDEDE00010001ull && c.subject.fabric_id == 0xFAB000000000001Dull);
    CHECK(c.issuer.icac_id == 0xCACACACA00000003ull && (c.issuer.has & MT_DN_HAS_ICAC));
    CHECK(!c.is_ca && c.key_usage == MT_KU_DIGITAL_SIGNATURE && c.n_eku == 2);
    CHECK(c.eku[0] == MT_EKU_CLIENT_AUTH && c.eku[1] == MT_EKU_SERVER_AUTH);
    CHECK(mt_cert_check_noc(&c) == MT_OK && mt_cert_check_ca(&c, false) != MT_OK);

    c = load("Node02_04");
    CHECK(c.subject.n_cats == 2 && c.subject.cats[0] == 0xABCE1002u && c.subject.cats[1] == 0xABCD0003u);
    c = load("Node02_05");
    CHECK(c.subject.n_cats >= 1 && c.subject.cats[0] == 0xABCD0010u);
    c = load("Node02_06");
    CHECK(c.n_future_ext == 2);
    c = load("ICA01");
    CHECK(c.is_ca && c.subject.icac_id == 0xCACACACA00000003ull && mt_cert_check_ca(&c, false) == MT_OK);
    CHECK(mt_cert_check_ca(&c, true) != MT_OK);
}

/* Find the certificate in the vector set whose SKID equals `akid`. */
static const struct vec *issuer_of(const mt_cert *c)
{
    for (size_t i = 0; i < NVECS; i++) {
        mt_cert p;
        if (mt_cert_decode(mt_span_of(VECS[i].tlv, VECS[i].tlv_len), &p)) continue;
        if (p.skid.len == c->akid.len && !memcmp(p.skid.p, c->akid.p, p.skid.len)) return &VECS[i];
    }
    return NULL;
}

static void test_signatures(void)
{
    uint8_t scratch[MT_CERT_SCRATCH];
    int verified = 0;
    for (size_t i = 0; i < NVECS; i++) {
        mt_cert c = load(VECS[i].name);
        const struct vec *p = issuer_of(&c);
        if (!p) { printf("  %s: issuer not in set\n", VECS[i].name); continue; }
        mt_cert pc = load(p->name);
        mt_err e = mt_cert_verify_sig(&c, pc.pubkey.p, mt_buf_of(scratch, sizeof scratch));
        if (e) printf("  %s signed by %s: %d\n", VECS[i].name, p->name, e);
        CHECK(e == MT_OK);
        verified++;
    }
    CHECK(verified >= 15);
    /* wrong issuer key */
    mt_cert n = load("Node01_01"), r = load("Root02");
    CHECK(mt_cert_verify_sig(&n, r.pubkey.p, mt_buf_of(scratch, sizeof scratch)) == MT_ERR_CRYPTO);
    CHECK(mt_cert_verify_sig(&n, r.pubkey.p, mt_buf_of(scratch, 20)) == MT_ERR_BUFFER_TOO_SMALL);
}

static mt_err chain(const char *noc, const char *icac, const char *rcac, uint32_t now)
{
    uint8_t scratch[MT_CERT_SCRATCH];
    mt_cert n = load(noc), i, r = load(rcac);
    if (icac) i = load(icac);
    return mt_cert_verify_chain(&n, icac ? &i : NULL, &r, now, mt_buf_of(scratch, sizeof scratch));
}

static void test_chain(void)
{
    uint32_t mid = 700000000u; /* 2022 */
    CHECK(chain("Node01_01", "ICA01", "Root01", 0) == MT_OK);            /* RCAC 1 -> ICA 3 -> NOC */
    CHECK(chain("Node01_02", NULL, "Root01", 0) == MT_OK);               /* RCAC 1 -> NOC */
    CHECK(chain("Node01_01", "ICA01", "Root01", mid) == MT_OK);
    CHECK(chain("Node01_01", NULL, "Root01", 0) != MT_OK);               /* ICAC missing */
    CHECK(chain("Node01_02", "ICA01", "Root01", 0) != MT_OK);            /* ICAC not the issuer */
    CHECK(chain("Node01_01", "ICA01", "Root02", 0) == MT_ERR_INVALID);   /* wrong root: issuer DN differs */
    CHECK(chain("Node01_01", "ICA02", "Root01", 0) != MT_OK);
    CHECK(chain("Root01", NULL, "Root01", 0) != MT_OK);                  /* a CA is not a NOC */
    /* validity: 2020-10-15 .. 2040-10-15 */
    CHECK(chain("Node01_01", "ICA01", "Root01", 1000u) == MT_ERR_EXPIRED);       /* before notBefore */
    CHECK(chain("Node01_01", "ICA01", "Root01", 1500000000u) == MT_ERR_EXPIRED); /* after notAfter */
}

/* Every operational-looking test certificate chains up to a root found through its AKID. */
static void test_chain_by_akid(void)
{
    int chains = 0;
    for (size_t k = 0; k < NVECS; k++) {
        mt_cert noc = load(VECS[k].name);
        if (mt_cert_check_noc(&noc)) continue;
        const struct vec *p = issuer_of(&noc), *icac = NULL, *root;
        CHECK(p != NULL);
        if (!p) continue;
        mt_cert pc = load(p->name);
        if (mt_cert_check_ca(&pc, true) == MT_OK) { root = p; }
        else { icac = p; root = issuer_of(&pc); }
        CHECK(root != NULL);
        if (!root) continue;
        mt_err e = chain(VECS[k].name, icac ? icac->name : NULL, root->name, 0);
        if (e) printf("  %s via %s -> %s: %d\n", VECS[k].name, icac ? icac->name : "-", root->name, e);
        CHECK(e == MT_OK);
        chains++;
    }
    CHECK(chains >= 10);
}

/* Corrupt copies of Node01_01 / ICA01 / Root01: every single-byte change must fail somewhere. */
static void test_tamper(void)
{
    uint8_t scratch[MT_CERT_SCRATCH], buf[MT_CERT_SCRATCH];
    const struct vec *vn = vec("Node01_01");
    mt_cert i = load("ICA01"), r = load("Root01"), n;
    int ok_changes = 0, bad = 0;
    for (size_t k = 0; k < vn->tlv_len; k++) {
        memcpy(buf, vn->tlv, vn->tlv_len);
        buf[k] ^= 0x01;
        if (mt_cert_decode(mt_span_of(buf, vn->tlv_len), &n)) continue;   /* structurally rejected */
        if (mt_cert_verify_chain(&n, &i, &r, 0, mt_buf_of(scratch, sizeof scratch)) == MT_OK) { ok_changes++; bad = (int)k; }
    }
    if (ok_changes) printf("  flip at %d still verifies\n", bad);
    CHECK(ok_changes == 0);
}

static void test_decode_negative(void)
{
    mt_cert c;
    const struct vec *v = vec("Node01_01");
    uint8_t buf[MT_CERT_SCRATCH + 1];   /* + 1: the oversize span below stays inside the array */
    int accepted = 0;
    for (size_t n = 0; n < v->tlv_len; n++)
        if (mt_cert_decode(mt_span_of(v->tlv, n), &c) == MT_OK) accepted++;
    CHECK(accepted == 0);                                   /* every proper prefix */
    memcpy(buf, v->tlv, v->tlv_len);
    buf[v->tlv_len] = 0;
    CHECK(mt_cert_decode(mt_span_of(buf, v->tlv_len + 1), &c) != MT_OK);   /* trailing garbage */
    CHECK(mt_cert_decode(mt_span_of(NULL, 0), &c) != MT_OK);
    CHECK(mt_cert_decode(mt_span_of(buf, MT_CERT_SCRATCH + 1), &c) == MT_ERR_INVALID);
    for (unsigned s = 1; s < 3000; s++) {                   /* random noise must not crash */
        for (size_t k = 0; k < 200; k++) buf[k] = (uint8_t)((s * 2654435761u >> (k % 24)) + k * s);
        buf[0] = 0x15;
        (void)mt_cert_decode(mt_span_of(buf, 200), &c);
    }
    /* mutated copies of a real certificate: whatever happens, no crash and no out-of-range spans */
    for (size_t k = 0; k < v->tlv_len; k++)
        for (int b = 0; b < 8; b++) {
            memcpy(buf, v->tlv, v->tlv_len);
            buf[k] ^= (uint8_t)(1 << b);
            if (mt_cert_decode(mt_span_of(buf, v->tlv_len), &c) == MT_OK)
                CHECK(c.pubkey.p >= buf && c.pubkey.p + c.pubkey.len <= buf + v->tlv_len);
        }
}

/* Dates around the UTCTime / GeneralizedTime switch, leap day and "no expiry". */
static int has(mt_span s, const char *needle)
{
    size_t n = strlen(needle);
    for (size_t i = 0; i + n <= s.len; i++)
        if (!memcmp(s.p + i, needle, n)) return 1;
    return 0;
}

static void test_times(void)
{
    uint8_t scratch[MT_CERT_SCRATCH];
    mt_cert c = load("Root01");
    mt_span tbs;
    struct { uint32_t nb, na; const char *a, *b; } t[] = {
        { 1577923199u, 1577923200u, "\x17\x0d" "491231235959Z", "\x18\x0f" "20500101000000Z" },
        { 5097600u, 0, "\x17\x0d" "000229000000Z", "\x18\x0f" "99991231235959Z" },
        { 0, 86399u, "\x17\x0d" "000101000000Z", "\x17\x0d" "000101235959Z" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        c.not_before = t[i].nb;
        c.not_after = t[i].na;
        CHECK(mt_cert_build_tbs(&c, mt_buf_of(scratch, sizeof scratch), &tbs) == MT_OK);
        if (!has(tbs, t[i].a) || !has(tbs, t[i].b)) printf("  time case %zu\n", i);
        CHECK(has(tbs, t[i].a) && has(tbs, t[i].b));
    }
}

/* ---- CSR ---- */

/* 1 when `openssl req -verify` printed "verify OK" (LibreSSL exits 0 even on a bad signature). */
static int openssl_csr_ok(mt_span csr, const char *path)
{
    char cmd[256], line[256];
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    fwrite(csr.p, 1, csr.len, f);
    fclose(f);
    snprintf(cmd, sizeof cmd, "openssl req -inform DER -in %s -verify -noout 2>&1", path);
    f = popen(cmd, "r");
    int ok = 0;
    while (f && fgets(line, sizeof line, f))
        if (strstr(line, "verify OK")) ok = 1;
    if (f) pclose(f);
    return ok;
}

static int have_openssl(void) { return system("openssl version > /dev/null 2>&1") == 0; }

static void test_csr(void)
{
    uint8_t seed = 9, priv[32], pub[65], out[256];
    mt_rng rng;
    mt_span csr;
    CHECK(mt_rng_init(&rng, counter_entropy, &seed) == MT_OK);
    CHECK(mt_crypto_p256_keygen(&rng, priv, pub) == MT_OK);
    CHECK(mt_cert_build_csr(&rng, priv, pub, mt_buf_of(out, sizeof out), &csr) == MT_OK);
    CHECK(csr.len > 180 && csr.len < 224 && csr.p[0] == 0x30);

    /* independent check: signature over CertificationRequestInfo with the embedded key */
    mt_span parts[3];
    der_split3(csr.p, parts);
    size_t n, h = der_hdr(parts[2].p, &n);
    uint8_t raw[64];
    CHECK(parts[2].p[0] == 0x03 && parts[2].p[h] == 0 && mt_crypto_p256_sig_from_der(mt_span_of(parts[2].p + h + 1, n - 1), raw) == MT_OK);
    CHECK(mt_crypto_p256_verify(pub, parts[0], raw) == MT_OK);
    CHECK(has(parts[0], "\x0c\x03" "CSR") && has(parts[0], "\x03\x42\x00\x04"));

    if (have_openssl()) {
        CHECK(openssl_csr_ok(csr, "build/csr_ok.der"));
        uint8_t bad[256];
        memcpy(bad, csr.p, csr.len);
        bad[csr.len - 3] ^= 0x40;                       /* inside the signature */
        CHECK(!openssl_csr_ok(mt_span_of(bad, csr.len), "build/csr_bad.der"));
        memcpy(bad, csr.p, csr.len);
        bad[60] ^= 0x01;                                /* inside the signed info */
        CHECK(!openssl_csr_ok(mt_span_of(bad, csr.len), "build/csr_bad2.der"));
    } else {
        printf("SKIP: openssl not found, CSR checked by the in-test verification only\n");
    }

    /* many keys: the DER signature length varies (70..72), every CSR must still parse and verify */
    for (int k = 0; k < 40; k++) {
        CHECK(mt_crypto_p256_keygen(&rng, priv, pub) == MT_OK);
        CHECK(mt_cert_build_csr(&rng, priv, pub, mt_buf_of(out, sizeof out), &csr) == MT_OK);
        der_split3(csr.p, parts);
        h = der_hdr(parts[2].p, &n);
        CHECK(mt_crypto_p256_sig_from_der(mt_span_of(parts[2].p + h + 1, n - 1), raw) == MT_OK &&
              mt_crypto_p256_verify(pub, parts[0], raw) == MT_OK);
    }
    CHECK(mt_cert_build_csr(&rng, priv, pub, mt_buf_of(out, 100), &csr) == MT_ERR_BUFFER_TOO_SMALL);
    mt_rng_free(&rng);
}

static void test_nocsr_elements(void)
{
    uint8_t seed = 3, priv[32], pub[65], nonce[32], out[300];
    mt_rng rng;
    mt_span el, csr, got;
    for (int i = 0; i < 32; i++) nonce[i] = (uint8_t)(0xa0 + i);
    CHECK(mt_rng_init(&rng, counter_entropy, &seed) == MT_OK);
    CHECK(mt_crypto_p256_keygen(&rng, priv, pub) == MT_OK);
    CHECK(mt_cert_build_nocsr_elements(&rng, priv, pub, nonce, mt_buf_of(out, sizeof out), &el) == MT_OK);
    mt_tlv_rd r;
    mt_tlv_rd_init(&r, el);
    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_STRUCT && mt_tlv_enter(&r) == MT_OK);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_is_ctx(&r, 1) && mt_tlv_get_bytes(&r, &csr) == MT_OK);
    CHECK(csr.p[0] == 0x30 && csr.len > 180);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_is_ctx(&r, 2) && mt_tlv_get_bytes(&r, &got) == MT_OK);
    CHECK(got.len == 32 && !memcmp(got.p, nonce, 32));
    CHECK(mt_tlv_next(&r) == MT_ERR_NOT_FOUND);
    CHECK(mt_cert_build_nocsr_elements(&rng, priv, pub, nonce, mt_buf_of(out, 50), &el) != MT_OK);
    mt_rng_free(&rng);
}

int main(void)
{
    test_all_vectors();
    test_fields();
    test_signatures();
    test_chain();
    test_chain_by_akid();
    test_tamper();
    test_decode_negative();
    test_times();
    test_csr();
    test_nocsr_elements();
    printf("%d checks, %d failures\n", checks, failures);
    return failures != 0;
}
