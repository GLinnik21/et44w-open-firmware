/* P-256 ECDH / ECDSA and the point and scalar primitives SPAKE2+ needs. */
#include <string.h>

#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mt_crypto.h"

#define SC MT_P256_SCALAR_LEN
#define PT MT_P256_POINT_LEN

/* Scratch for one operation: the curve plus three points and three integers. */
typedef struct {
    mbedtls_ecp_group g;
    mbedtls_ecp_point p, q, r;
    mbedtls_mpi a, b, c;
} ec;

static int ec_open(ec *e)
{
    mbedtls_ecp_group_init(&e->g);
    mbedtls_ecp_point_init(&e->p);
    mbedtls_ecp_point_init(&e->q);
    mbedtls_ecp_point_init(&e->r);
    mbedtls_mpi_init(&e->a);
    mbedtls_mpi_init(&e->b);
    mbedtls_mpi_init(&e->c);
    return mbedtls_ecp_group_load(&e->g, MBEDTLS_ECP_DP_SECP256R1);
}

static mt_err ec_close(ec *e, int r)
{
    mbedtls_mpi_free(&e->c);
    mbedtls_mpi_free(&e->b);
    mbedtls_mpi_free(&e->a);
    mbedtls_ecp_point_free(&e->r);
    mbedtls_ecp_point_free(&e->q);
    mbedtls_ecp_point_free(&e->p);
    mbedtls_ecp_group_free(&e->g);
    return r == 0 ? MT_OK : MT_ERR_CRYPTO;
}

/* A point must be on the curve; read_binary alone only range-checks the coordinates. */
static int read_pt(ec *e, mbedtls_ecp_point *p, const uint8_t *b)
{
    int r = mbedtls_ecp_point_read_binary(&e->g, p, b, PT);
    return r ? r : mbedtls_ecp_check_pubkey(&e->g, p);
}

static int write_pt(ec *e, const mbedtls_ecp_point *p, uint8_t *out)
{
    size_t n;
    if (mbedtls_ecp_is_zero((mbedtls_ecp_point *)p)) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }
    return mbedtls_ecp_point_write_binary(&e->g, p, MBEDTLS_ECP_PF_UNCOMPRESSED, &n, out, PT);
}

static int read_sc(mbedtls_mpi *m, const uint8_t *b) { return mbedtls_mpi_read_binary(m, b, SC); }
static int write_sc(const mbedtls_mpi *m, uint8_t *b) { return mbedtls_mpi_write_binary(m, b, SC); }

mt_err mt_crypto_p256_keygen(mt_rng *rng, uint8_t priv[SC], uint8_t pub[PT])
{
    ec e;
    int r = ec_open(&e);
    if (!r) r = mbedtls_ecp_gen_keypair(&e.g, &e.a, &e.p, mbedtls_ctr_drbg_random, &rng->d);
    if (!r) r = write_sc(&e.a, priv);
    if (!r) r = write_pt(&e, &e.p, pub);
    return ec_close(&e, r);
}

mt_err mt_crypto_p256_ecdh(mt_rng *rng, const uint8_t priv[SC], const uint8_t peer[PT], uint8_t secret[SC])
{
    ec e;
    int r = ec_open(&e);
    if (!r) r = read_sc(&e.a, priv);
    if (!r) r = read_pt(&e, &e.p, peer);
    if (!r) r = mbedtls_ecdh_compute_shared(&e.g, &e.b, &e.p, &e.a, mbedtls_ctr_drbg_random, &rng->d);
    if (!r) r = write_sc(&e.b, secret);
    return ec_close(&e, r);
}

mt_err mt_crypto_p256_sign(mt_rng *rng, const uint8_t priv[SC], mt_span msg, uint8_t sig[MT_P256_SIG_LEN])
{
    ec e;
    uint8_t h[MT_SHA256_LEN];
    int r = ec_open(&e);
    mt_crypto_sha256(msg, h);
    if (!r) r = read_sc(&e.a, priv);
    if (!r) r = mbedtls_ecdsa_sign(&e.g, &e.b, &e.c, &e.a, h, sizeof h, mbedtls_ctr_drbg_random, &rng->d);
    if (!r) r = write_sc(&e.b, sig);
    if (!r) r = write_sc(&e.c, sig + SC);
    return ec_close(&e, r);
}

mt_err mt_crypto_p256_verify(const uint8_t pub[PT], mt_span msg, const uint8_t sig[MT_P256_SIG_LEN])
{
    ec e;
    uint8_t h[MT_SHA256_LEN];
    int r = ec_open(&e);
    mt_crypto_sha256(msg, h);
    if (!r) r = read_pt(&e, &e.p, pub);
    if (!r) r = read_sc(&e.b, sig);
    if (!r) r = read_sc(&e.c, sig + SC);
    if (!r) r = mbedtls_ecdsa_verify(&e.g, h, sizeof h, &e.p, &e.b, &e.c);
    return ec_close(&e, r);
}

size_t mt_crypto_p256_sig_to_der(const uint8_t sig[MT_P256_SIG_LEN], uint8_t der_out[MT_P256_SIG_DER_MAX])
{
    uint8_t buf[MT_P256_SIG_DER_MAX];
    uint8_t *p = buf + sizeof buf;
    mbedtls_mpi r, s;
    size_t n;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    read_sc(&r, sig);
    read_sc(&s, sig + SC);
    /* Writes backwards from the end; 32-byte values always fit the buffer, so no error is possible. */
    n = (size_t)mbedtls_asn1_write_mpi(&p, buf, &s);
    n += (size_t)mbedtls_asn1_write_mpi(&p, buf, &r);
    n += (size_t)mbedtls_asn1_write_len(&p, buf, n);
    n += (size_t)mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    memcpy(der_out, p, n);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return n;
}

/* One DER INTEGER that must be non-negative: mbedtls_asn1_get_mpi reads the content as unsigned, so a set sign bit
 * (a negative value) or an empty content would otherwise pass as a positive number. */
static int get_uint(unsigned char **p, const unsigned char *end, mbedtls_mpi *m)
{
    size_t n;
    int x = mbedtls_asn1_get_tag(p, end, &n, MBEDTLS_ASN1_INTEGER);
    if (x) return x;
    if (n == 0 || (**p & 0x80)) return MBEDTLS_ERR_ASN1_INVALID_DATA;
    x = mbedtls_mpi_read_binary(m, *p, n);
    *p += n;
    return x;
}

mt_err mt_crypto_p256_sig_from_der(mt_span der, uint8_t sig[MT_P256_SIG_LEN])
{
    unsigned char *p = (unsigned char *)der.p; /* the asn1 parser only reads */
    const unsigned char *end = der.p + der.len;
    mbedtls_mpi r, s;
    size_t n;
    int x = mbedtls_asn1_get_tag(&p, end, &n, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    if (!x && p + n != end) x = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    if (!x) x = get_uint(&p, end, &r);
    if (!x) x = get_uint(&p, end, &s);
    if (!x && p != end) x = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    if (!x) x = write_sc(&r, sig); /* fails when a value needs more than 32 bytes */
    if (!x) x = write_sc(&s, sig + SC);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return x ? MT_ERR_INVALID : MT_OK;
}

mt_err mt_crypto_p256_point_check(const uint8_t pt[PT])
{
    ec e;
    int r = ec_open(&e);
    if (!r) r = read_pt(&e, &e.p, pt);
    if (!r && mbedtls_ecp_is_zero(&e.p)) r = MBEDTLS_ERR_ECP_INVALID_KEY;
    return ec_close(&e, r);
}

mt_err mt_crypto_p256_point_mul(mt_rng *rng, const uint8_t k[SC], const uint8_t *p, uint8_t out[PT])
{
    ec e;
    int r = ec_open(&e);
    if (!r) r = read_sc(&e.a, k);
    if (!r) r = p ? read_pt(&e, &e.p, p) : mbedtls_ecp_copy(&e.p, &e.g.G);
    if (!r) r = mbedtls_ecp_mul(&e.g, &e.r, &e.a, &e.p, mbedtls_ctr_drbg_random, &rng->d);
    if (!r) r = write_pt(&e, &e.r, out);
    return ec_close(&e, r);
}

/* r = P + Q with mbedtls_ecp_muladd's scalar-1 shortcut (a copy and one addition; both scalars are public). */
static int add_pts(ec *e, mbedtls_ecp_point *r, const mbedtls_ecp_point *p, const mbedtls_ecp_point *q)
{
    int x = mbedtls_mpi_lset(&e->c, 1);
    return x ? x : mbedtls_ecp_muladd(&e->g, r, &e->c, p, &e->c, q);
}

/* mbedtls_ecp_muladd is variable-time in its scalars, so each product goes through the blinded mbedtls_ecp_mul
 * (the scalars here are secrets: SPAKE2+ y and w0) and only the sum of the two points is left to it. */
mt_err mt_crypto_p256_point_muladd(mt_rng *rng, const uint8_t a[SC], const uint8_t *p, const uint8_t b[SC],
                                   const uint8_t q[PT], uint8_t out[PT])
{
    ec e;
    int r = ec_open(&e);
    if (!r) r = read_sc(&e.a, a);
    if (!r) r = read_sc(&e.b, b);
    if (!r) r = p ? read_pt(&e, &e.p, p) : mbedtls_ecp_copy(&e.p, &e.g.G);
    if (!r) r = read_pt(&e, &e.q, q);
    if (!r) r = mbedtls_ecp_mul(&e.g, &e.r, &e.a, &e.p, mbedtls_ctr_drbg_random, &rng->d); /* r = a*P */
    if (!r) r = mbedtls_ecp_mul(&e.g, &e.p, &e.b, &e.q, mbedtls_ctr_drbg_random, &rng->d); /* p = b*Q */
    if (!r) r = add_pts(&e, &e.q, &e.r, &e.p);
    if (!r) r = write_pt(&e, &e.q, out);
    return ec_close(&e, r);
}

mt_err mt_crypto_p256_point_add(const uint8_t p[PT], const uint8_t q[PT], uint8_t out[PT])
{
    ec e;
    int r = ec_open(&e);
    if (!r) r = read_pt(&e, &e.p, p);
    if (!r) r = read_pt(&e, &e.q, q);
    if (!r) r = add_pts(&e, &e.r, &e.p, &e.q);
    if (!r) r = write_pt(&e, &e.r, out);
    return ec_close(&e, r);
}

mt_err mt_crypto_p256_scalar_reduce(mt_span in, uint8_t out[SC])
{
    ec e;
    int r = ec_open(&e);
    if (!r) r = mbedtls_mpi_read_binary(&e.a, in.p, in.len);
    if (!r) r = mbedtls_mpi_mod_mpi(&e.b, &e.a, &e.g.N);
    if (!r) r = write_sc(&e.b, out);
    return ec_close(&e, r);
}

mt_err mt_crypto_p256_scalar_neg(const uint8_t s[SC], uint8_t out[SC])
{
    ec e;
    int r = ec_open(&e);
    if (!r) r = read_sc(&e.a, s);
    if (!r) r = mbedtls_mpi_mod_mpi(&e.b, &e.a, &e.g.N);
    if (!r) r = mbedtls_mpi_sub_mpi(&e.c, &e.g.N, &e.b); /* n for s == 0 */
    if (!r) r = mbedtls_mpi_mod_mpi(&e.a, &e.c, &e.g.N);
    if (!r) r = write_sc(&e.a, out);
    return ec_close(&e, r);
}

mt_err mt_crypto_p256_scalar_mul(const uint8_t a[SC], const uint8_t b[SC], uint8_t out[SC])
{
    ec e;
    int r = ec_open(&e);
    if (!r) r = read_sc(&e.a, a);
    if (!r) r = read_sc(&e.b, b);
    if (!r) r = mbedtls_mpi_mul_mpi(&e.c, &e.a, &e.b);
    if (!r) r = mbedtls_mpi_mod_mpi(&e.a, &e.c, &e.g.N);
    if (!r) r = write_sc(&e.a, out);
    return ec_close(&e, r);
}
