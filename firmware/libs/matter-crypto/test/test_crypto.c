/* Host tests for matter-crypto. Vector sources:
 *  - SHA-256: FIPS 180-2 "abc" and empty message.
 *  - HMAC-SHA256: RFC 4231 test cases 1, 2, 6.
 *  - HKDF-SHA256: RFC 5869 appendix A.1-A.3.
 *  - ECDSA P-256 / SHA-256: RFC 6979 appendix A.2.5 ("sample"; key, public point and r||s).
 *  - AES-128-CCM (13-byte nonce, 16-byte tag), ECDH, ECDSA verify, DER signature conversion and
 *    scalar multiplication mod n: connectedhomeip src/crypto/tests (official_vectors.h, ccm_vectors.h;
 *    the CCM set is Wycheproof, ECDSA is RFC 6979 A.2.5 plus OpenSSL deterministic signatures).
 *    Everything else (round trips, tamper checks, edge cases) is self-consistency, not a reference.
 */
#include <stdio.h>
#include <string.h>

#include "ccm_vectors.h"
#include "mt_crypto.h"
#include "official_vectors.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static size_t unhex(const char *s, uint8_t *out)
{
    size_t n = 0;
    unsigned v;
    while (s[0] && s[1]) {
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

static int eqhex(const uint8_t *got, size_t len, const char *hex)
{
    uint8_t want[256];
    return unhex(hex, want) == len && memcmp(got, want, len) == 0;
}

static void fill(uint8_t *p, size_t n, uint8_t start)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(start + i);
}

static int counter_entropy(void *ctx, uint8_t *out, size_t len)
{
    uint8_t *c = ctx;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)((*c)++ * 37 + 11);
    return 0;
}

#define K "abc"

static void test_sha(void)
{
    uint8_t h[32];
    mt_sha256 s;
    mt_crypto_sha256(mt_span_of(K, 3), h);
    CHECK(eqhex(h, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    mt_crypto_sha256(mt_span_of(K, 0), h);
    CHECK(eqhex(h, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    mt_sha256_begin(&s);
    mt_sha256_update(&s, mt_span_of("a", 1));
    mt_sha256_peek(&s, h); /* SHA-256("a"); the running hash continues */
    CHECK(eqhex(h, 32, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"));
    mt_sha256_update(&s, mt_span_of("bc", 2));
    mt_sha256_finish(&s, h);
    CHECK(eqhex(h, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

static void test_hmac(void)
{
    uint8_t key[131], h[32];
    memset(key, 0x0b, 20);
    CHECK(mt_crypto_hmac_sha256(mt_span_of(key, 20), mt_span_of("Hi There", 8), h) == MT_OK);
    CHECK(eqhex(h, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    CHECK(mt_crypto_hmac_sha256(mt_span_of("Jefe", 4), mt_span_of("what do ya want for nothing?", 28), h) == MT_OK);
    CHECK(eqhex(h, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    memset(key, 0xaa, 131);
    CHECK(mt_crypto_hmac_sha256(mt_span_of(key, 131),
          mt_span_of("Test Using Larger Than Block-Size Key - Hash Key First", 54), h) == MT_OK);
    CHECK(eqhex(h, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
}

static void test_hkdf(void)
{
    uint8_t ikm[80], salt[80], info[80], okm[82];
    memset(ikm, 0x0b, 22);
    fill(salt, 13, 0);
    fill(info, 10, 0xf0);
    CHECK(mt_crypto_hkdf_sha256(mt_span_of(salt, 13), mt_span_of(ikm, 22), mt_span_of(info, 10), mt_buf_of(okm, 42)) == MT_OK);
    CHECK(eqhex(okm, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    fill(ikm, 80, 0);
    fill(salt, 80, 0x60);
    fill(info, 80, 0xb0);
    CHECK(mt_crypto_hkdf_sha256(mt_span_of(salt, 80), mt_span_of(ikm, 80), mt_span_of(info, 80), mt_buf_of(okm, 82)) == MT_OK);
    CHECK(eqhex(okm, 82, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"));
    memset(ikm, 0x0b, 22);
    CHECK(mt_crypto_hkdf_sha256(mt_span_of(NULL, 0), mt_span_of(ikm, 22), mt_span_of(NULL, 0), mt_buf_of(okm, 42)) == MT_OK);
    CHECK(eqhex(okm, 42, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));
}

static void test_ccm(void)
{
    uint8_t key[16], nonce[13], aad[8], pt[23], ct[64], back[64];
    size_t n = 0, m = 0;
    for (size_t i = 0; i < sizeof CCM_VECTORS / sizeof CCM_VECTORS[0]; i++) {
        uint8_t k[16], nn[13], ad[32], p[32], c[64], t[16], in[48], got[64];
        size_t adl = unhex(CCM_VECTORS[i].aad, ad), pl = unhex(CCM_VECTORS[i].pt, p);
        unhex(CCM_VECTORS[i].key, k); unhex(CCM_VECTORS[i].nonce, nn);
        size_t cl = unhex(CCM_VECTORS[i].ct, c);
        unhex(CCM_VECTORS[i].tag, t);
        memcpy(in, c, cl); memcpy(in + cl, t, 16);
        CHECK(mt_crypto_ccm_encrypt(k, nn, mt_span_of(ad, adl), mt_span_of(p, pl), mt_buf_of(got, sizeof got), &n) == MT_OK
              && n == cl + 16 && memcmp(got, in, n) == 0);
        CHECK(mt_crypto_ccm_decrypt(k, nn, mt_span_of(ad, adl), mt_span_of(in, cl + 16), mt_buf_of(got, sizeof got), &m) == MT_OK
              && m == pl && memcmp(got, p, pl) == 0);
        in[cl + 15] ^= 0x80; /* a damaged tag never verifies */
        CHECK(mt_crypto_ccm_decrypt(k, nn, mt_span_of(ad, adl), mt_span_of(in, cl + 16), mt_buf_of(got, sizeof got), &m) == MT_ERR_CRYPTO);
    }
    fill(key, 16, 0);
    fill(nonce, 13, 0x10);
    fill(aad, 8, 0);
    fill(pt, 23, 0x20);
    CHECK(mt_crypto_ccm_encrypt(key, nonce, mt_span_of(aad, 8), mt_span_of(pt, 23), mt_buf_of(ct, 39), &n) == MT_OK);
    CHECK(n == 39);
    CHECK(mt_crypto_ccm_decrypt(key, nonce, mt_span_of(aad, 8), mt_span_of(ct, 39), mt_buf_of(back, 23), &m) == MT_OK);
    CHECK(m == 23 && memcmp(back, pt, 23) == 0);
    CHECK(mt_crypto_ccm_encrypt(key, nonce, mt_span_of(aad, 8), mt_span_of(pt, 23), mt_buf_of(ct, 38), &n) == MT_ERR_BUFFER_TOO_SMALL);
    CHECK(mt_crypto_ccm_decrypt(key, nonce, mt_span_of(aad, 8), mt_span_of(ct, 15), mt_buf_of(back, 64), &m) == MT_ERR_INVALID);
    CHECK(mt_crypto_ccm_decrypt(key, nonce, mt_span_of(aad, 8), mt_span_of(ct, 39), mt_buf_of(back, 22), &m) == MT_ERR_BUFFER_TOO_SMALL);
    ct[38] ^= 1; /* tag */
    CHECK(mt_crypto_ccm_decrypt(key, nonce, mt_span_of(aad, 8), mt_span_of(ct, 39), mt_buf_of(back, 23), &m) == MT_ERR_CRYPTO);
    ct[38] ^= 1;
    ct[0] ^= 1; /* ciphertext */
    CHECK(mt_crypto_ccm_decrypt(key, nonce, mt_span_of(aad, 8), mt_span_of(ct, 39), mt_buf_of(back, 23), &m) == MT_ERR_CRYPTO);
    ct[0] ^= 1;
    aad[0] ^= 1;
    CHECK(mt_crypto_ccm_decrypt(key, nonce, mt_span_of(aad, 8), mt_span_of(ct, 39), mt_buf_of(back, 23), &m) == MT_ERR_CRYPTO);
    aad[0] ^= 1;
    /* Empty plaintext: the output is just the tag. */
    CHECK(mt_crypto_ccm_encrypt(key, nonce, mt_span_of(aad, 8), mt_span_of(pt, 0), mt_buf_of(ct, 16), &n) == MT_OK && n == 16);
    CHECK(mt_crypto_ccm_decrypt(key, nonce, mt_span_of(aad, 8), mt_span_of(ct, 16), mt_buf_of(back, 0), &m) == MT_OK && m == 0);
}

static const char *A_PRIV = "254dca182530bb1d6d132cded6237b2ed91e3f721fcb1971174494d6493c9d5d";
static const char *A_PUB = "048ff01b22f260bfbcb37c1f0e10bbf21abee25addafa81d581770b3680b01db39ab684d43a45295d94d8068d5db70a98e8e5542c79d3b9d600ff6d0dcd37e1f09";
static const char *B_PRIV = "3460be31201e69fedaa0eee8b9997f5c7c2999fdafe593253cd654af4dfad715";
static const char *B_PUB = "047cc9f126ef6f44cac8a8c3763a144fdab1fce00b5d1a245861ed93595318aeecc859de1b18b4bd8fa3d56bc128e04895e9f247f64f39b6990b8b70c43877956d";
static const char *MSG = "matter crypto test message";

static void test_ecdh_keys(mt_rng *rng)
{
    uint8_t a[32], apub[65], b[32], bpub[65], s1[32], s2[32], g[65], k[32], kpub[65];
    unhex(A_PRIV, a); unhex(A_PUB, apub); unhex(B_PRIV, b); unhex(B_PUB, bpub);
    for (size_t i = 0; i < sizeof ECDH_VECTORS / sizeof ECDH_VECTORS[0]; i++) {
        uint8_t kp[32], pp[65];
        unhex(ECDH_VECTORS[i].priv, kp); unhex(ECDH_VECTORS[i].peer, pp);
        CHECK(mt_crypto_p256_ecdh(rng, kp, pp, s1) == MT_OK && eqhex(s1, 32, ECDH_VECTORS[i].secret));
    }
    CHECK(mt_crypto_p256_ecdh(rng, a, bpub, s1) == MT_OK);
    CHECK(mt_crypto_p256_ecdh(rng, b, apub, s2) == MT_OK && memcmp(s1, s2, 32) == 0);
    /* priv * G reproduces the public point */
    CHECK(mt_crypto_p256_point_mul(rng, a, NULL, g) == MT_OK && memcmp(g, apub, 65) == 0);
    /* generated pairs are consistent and ECDH-compatible */
    CHECK(mt_crypto_p256_keygen(rng, k, kpub) == MT_OK);
    CHECK(mt_crypto_p256_point_mul(rng, k, NULL, g) == MT_OK && memcmp(g, kpub, 65) == 0);
    CHECK(mt_crypto_p256_ecdh(rng, k, apub, s1) == MT_OK && mt_crypto_p256_ecdh(rng, a, kpub, s2) == MT_OK
          && memcmp(s1, s2, 32) == 0);
    /* a point off the curve is refused */
    bpub[64] ^= 1;
    CHECK(mt_crypto_p256_ecdh(rng, a, bpub, s1) == MT_ERR_CRYPTO);
    CHECK(mt_crypto_p256_point_check(bpub) == MT_ERR_CRYPTO);
    CHECK(mt_crypto_p256_point_check(apub) == MT_OK);
    memset(bpub, 0, 65);
    CHECK(mt_crypto_p256_point_check(bpub) == MT_ERR_CRYPTO);
}

static void test_ecdsa(mt_rng *rng)
{
    uint8_t a[32], apub[65], sig[64], sig2[64], der[72], d2[64];
    const char *rfc_sig = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                          "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";
    uint8_t rpriv[32], rpub[65], rsig[64];
    mt_span msg = mt_span_of(MSG, strlen(MSG));
    size_t n;

    unhex(A_PRIV, a); unhex(A_PUB, apub);
    CHECK(mt_crypto_p256_sign(rng, a, msg, sig) == MT_OK);
    CHECK(mt_crypto_p256_verify(apub, msg, sig) == MT_OK);
    sig[10] ^= 1;
    CHECK(mt_crypto_p256_verify(apub, msg, sig) == MT_ERR_CRYPTO);
    sig[10] ^= 1;
    CHECK(mt_crypto_p256_verify(apub, mt_span_of(MSG, strlen(MSG) - 1), sig) == MT_ERR_CRYPTO);
    memset(sig2, 0, 64);
    CHECK(mt_crypto_p256_verify(apub, msg, sig2) == MT_ERR_CRYPTO);

    /* official signatures (RFC 6979 A.2.5 and OpenSSL deterministic ECDSA) verify; a changed message fails */
    for (size_t i = 0; i < sizeof ECDSA_VECTORS / sizeof ECDSA_VECTORS[0]; i++) {
        uint8_t vp[65], vs[64];
        size_t ml = strlen(ECDSA_VECTORS[i].msg);
        unhex(ECDSA_VECTORS[i].pub, vp); unhex(ECDSA_VECTORS[i].sig, vs);
        CHECK(mt_crypto_p256_verify(vp, mt_span_of(ECDSA_VECTORS[i].msg, ml), vs) == MT_OK);
        CHECK(mt_crypto_p256_verify(vp, mt_span_of(ECDSA_VECTORS[i].msg, ml - 1), vs) == MT_ERR_CRYPTO);
    }

    /* RFC 6979 A.2.5: the "sample" signature produced by deterministic ECDSA */
    unhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", rpriv);
    unhex("0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299", rpub);
    unhex(rfc_sig, rsig);
    CHECK(mt_crypto_p256_verify(rpub, mt_span_of("sample", 6), rsig) == MT_OK);
    CHECK(mt_crypto_p256_verify(rpub, mt_span_of("Sample", 6), rsig) == MT_ERR_CRYPTO);

    /* sign / verify round trip with a random k; two signatures differ */
    CHECK(mt_crypto_p256_sign(rng, rpriv, mt_span_of("sample", 6), sig) == MT_OK);
    CHECK(mt_crypto_p256_verify(rpub, mt_span_of("sample", 6), sig) == MT_OK);
    CHECK(mt_crypto_p256_sign(rng, rpriv, mt_span_of("sample", 6), sig2) == MT_OK);
    CHECK(memcmp(sig, sig2, 64) != 0);

    /* DER: official conversion vectors both ways; a high-bit r gets a 00 pad */
    for (size_t i = 0; i < sizeof DER_VECTORS / sizeof DER_VECTORS[0]; i++) {
        uint8_t raw[64], want[72];
        size_t wl = unhex(DER_VECTORS[i].der, want);
        unhex(DER_VECTORS[i].raw, raw);
        n = mt_crypto_p256_sig_to_der(raw, der);
        CHECK(n == wl && memcmp(der, want, n) == 0);
        CHECK(mt_crypto_p256_sig_from_der(mt_span_of(want, wl), d2) == MT_OK && memcmp(d2, raw, 64) == 0);
    }
    memset(sig, 0, 64);
    sig[0] = 0x80;
    sig[63] = 1;
    n = mt_crypto_p256_sig_to_der(sig, der);
    CHECK(n == 40 && der[0] == 0x30 && der[1] == 38 && der[2] == 2 && der[3] == 33 && der[4] == 0 && der[5] == 0x80
          && der[37] == 2 && der[38] == 1 && der[39] == 1);
    CHECK(mt_crypto_p256_sig_from_der(mt_span_of(der, n), d2) == MT_OK && memcmp(d2, sig, 64) == 0);
    memset(sig, 0, 64); /* short integers are left-padded back to 32 bytes */
    sig[31] = 5; sig[63] = 7;
    n = mt_crypto_p256_sig_to_der(sig, der);
    CHECK(n == 8 && mt_crypto_p256_sig_from_der(mt_span_of(der, n), d2) == MT_OK && memcmp(d2, sig, 64) == 0);

    /* malformed DER */
    CHECK(mt_crypto_p256_sig_from_der(mt_span_of(der, n - 1), d2) == MT_ERR_INVALID);
    der[n] = 0;
    CHECK(mt_crypto_p256_sig_from_der(mt_span_of(der, n + 1), d2) == MT_ERR_INVALID);
    der[0] = 0x31;
    CHECK(mt_crypto_p256_sig_from_der(mt_span_of(der, n), d2) == MT_ERR_INVALID);
    /* r = 01 ff 00..00 needs 33 significant bytes: does not fit a P-256 scalar */
    unhex("3026022101ff00000000000000000000000000000000000000000000000000000000000000020101", der);
    CHECK(mt_crypto_p256_sig_from_der(mt_span_of(der, 40), d2) == MT_ERR_INVALID);
    /* negative INTEGERs (sign bit set, no 00 pad) and empty INTEGERs are not unsigned values */
    unhex("300602018002017f", der);
    CHECK(mt_crypto_p256_sig_from_der(mt_span_of(der, 8), d2) == MT_ERR_INVALID);
    unhex("300602017f0201ff", der);
    CHECK(mt_crypto_p256_sig_from_der(mt_span_of(der, 8), d2) == MT_ERR_INVALID);
    unhex("302502208000000000000000000000000000000000000000000000000000000000000000020101", der);
    CHECK(mt_crypto_p256_sig_from_der(mt_span_of(der, 39), d2) == MT_ERR_INVALID);
    unhex("30050200020101", der);
    CHECK(mt_crypto_p256_sig_from_der(mt_span_of(der, 7), d2) == MT_ERR_INVALID);
    unhex("300602017f02017f", der);
    CHECK(mt_crypto_p256_sig_from_der(mt_span_of(der, 8), d2) == MT_OK && d2[31] == 0x7f && d2[63] == 0x7f);
}

static void test_points(mt_rng *rng)
{
    uint8_t a[32], apub[65], b[32], bpub[65], one[32] = { [31] = 1 }, five[32] = { [31] = 5 };
    uint8_t x[65], y[65], z[65], t[32], u[32], ng[65];
    uint8_t big[33];

    unhex(A_PRIV, a); unhex(A_PUB, apub); unhex(B_PRIV, b); unhex(B_PUB, bpub);

    /* a*G + b*Q == (a*G) + (b*Q) */
    CHECK(mt_crypto_p256_point_mul(rng, b, bpub, x) == MT_OK);
    CHECK(mt_crypto_p256_point_muladd(rng, a, apub, b, bpub, y) == MT_OK);
    CHECK(mt_crypto_p256_point_mul(rng, a, apub, z) == MT_OK);
    CHECK(mt_crypto_p256_point_add(x, z, x) == MT_OK && memcmp(x, y, 65) == 0);
    CHECK(mt_crypto_p256_point_add(apub, bpub, z) == MT_OK);
    CHECK(mt_crypto_p256_point_muladd(rng, one, apub, one, bpub, y) == MT_OK && memcmp(y, z, 65) == 0);
    CHECK(mt_crypto_p256_point_muladd(rng, a, NULL, one, bpub, y) == MT_OK && memcmp(y, z, 65) == 0); /* NULL = G */

    /* P + (-1)*P is infinity, which is reported as an error */
    CHECK(mt_crypto_p256_scalar_neg(one, t) == MT_OK);
    CHECK(mt_crypto_p256_point_muladd(rng, one, apub, t, apub, y) == MT_ERR_CRYPTO);
    /* P - Q via a negated scalar, then adding Q back gives P */
    CHECK(mt_crypto_p256_point_muladd(rng, one, apub, t, bpub, x) == MT_OK);
    CHECK(mt_crypto_p256_point_add(x, bpub, y) == MT_OK && memcmp(y, apub, 65) == 0);
    /* neg(neg(s)) == s, neg(0) == 0 */
    CHECK(mt_crypto_p256_scalar_neg(t, u) == MT_OK && memcmp(u, one, 32) == 0);
    memset(u, 0, 32);
    CHECK(mt_crypto_p256_scalar_neg(u, t) == MT_OK && memcmp(t, u, 32) == 0);

    /* reduction: n + 5 -> 5; n -> 0; a short input is left-padded; neg(5) = n - 5 */
    unhex("00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632556", big);
    CHECK(mt_crypto_p256_scalar_reduce(mt_span_of(big, 33), t) == MT_OK && memcmp(t, five, 32) == 0);
    unhex("00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", big);
    CHECK(mt_crypto_p256_scalar_reduce(mt_span_of(big, 33), t) == MT_OK && memcmp(t, u, 32) == 0);
    CHECK(mt_crypto_p256_scalar_reduce(mt_span_of(five + 31, 1), t) == MT_OK && memcmp(t, five, 32) == 0);
    CHECK(mt_crypto_p256_scalar_neg(five, t) == MT_OK);
    CHECK(eqhex(t, 32, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254c"));
    /* (n-5)*G is the negation of 5*G: same X, Y = p - Y; their sum is infinity */
    CHECK(mt_crypto_p256_point_mul(rng, five, NULL, x) == MT_OK && mt_crypto_p256_point_mul(rng, t, NULL, ng) == MT_OK);
    CHECK(memcmp(x + 1, ng + 1, 32) == 0 && memcmp(x + 33, ng + 33, 32) != 0);
    CHECK(mt_crypto_p256_point_add(x, ng, y) == MT_ERR_CRYPTO);
    /* a*b mod n: official vectors, aliasing, and n-1 squared is 1 */
    for (size_t i = 0; i < sizeof FE_MUL_VECTORS / sizeof FE_MUL_VECTORS[0]; i++) {
        uint8_t fa[32], fb[32], fo[32];
        unhex(FE_MUL_VECTORS[i].a, fa); unhex(FE_MUL_VECTORS[i].b, fb);
        CHECK(mt_crypto_p256_scalar_mul(fa, fb, fo) == MT_OK && eqhex(fo, 32, FE_MUL_VECTORS[i].out));
        CHECK(mt_crypto_p256_scalar_mul(fa, fb, fa) == MT_OK && eqhex(fa, 32, FE_MUL_VECTORS[i].out));
    }
    CHECK(mt_crypto_p256_scalar_neg(one, t) == MT_OK);
    CHECK(mt_crypto_p256_scalar_mul(t, t, u) == MT_OK && memcmp(u, one, 32) == 0);
    memset(u, 0, 32);
    /* a zero scalar gives infinity; muladd's blinded multiplications refuse it too */
    CHECK(mt_crypto_p256_point_mul(rng, u, NULL, x) == MT_ERR_CRYPTO);
    CHECK(mt_crypto_p256_point_muladd(rng, u, apub, one, bpub, x) == MT_ERR_CRYPTO);
    CHECK(mt_crypto_p256_point_muladd(rng, one, apub, u, bpub, x) == MT_ERR_CRYPTO);
    /* invalid inputs */
    apub[3] ^= 1;
    CHECK(mt_crypto_p256_point_add(apub, bpub, z) == MT_ERR_CRYPTO);
    CHECK(mt_crypto_p256_point_mul(rng, a, apub, z) == MT_ERR_CRYPTO);
}

static void test_rng(void)
{
    uint8_t seed = 1, a[32], b[32];
    mt_rng r;
    CHECK(mt_rng_init(&r, counter_entropy, &seed) == MT_OK);
    CHECK(mt_rng_fill(&r, a, 32) == MT_OK && mt_rng_fill(&r, b, 32) == MT_OK);
    CHECK(memcmp(a, b, 32) != 0);
    mt_rng_free(&r);
}

int main(void)
{
    uint8_t seed = 5;
    mt_rng rng;

    CHECK(mt_rng_init(&rng, counter_entropy, &seed) == MT_OK);
    test_sha();
    test_hmac();
    test_hkdf();
    test_ccm();
    test_ecdh_keys(&rng);
    test_ecdsa(&rng);
    test_points(&rng);
    test_rng();
    mt_rng_free(&rng);
    printf("%d checks, %d failures\n", checks, failures);
    return failures != 0;
}
