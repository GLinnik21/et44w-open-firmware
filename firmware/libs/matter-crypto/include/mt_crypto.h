/* Matter crypto facade over mbedtls 3.1. Fixed-size byte arrays, no allocation (mbedtls's transient
 * ECP/bignum heap use aside). Keys are raw big-endian scalars (32 B); points are uncompressed X9.62
 * (65 B, 0x04 || X || Y); ECDSA signatures are raw r||s (64 B) with explicit DER conversion. */
#ifndef MT_CRYPTO_H
#define MT_CRYPTO_H

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mt_core.h"

#define MT_SHA256_LEN 32
#define MT_P256_SCALAR_LEN 32
#define MT_P256_POINT_LEN 65
#define MT_P256_SIG_LEN 64
#define MT_P256_SIG_DER_MAX 72
#define MT_CCM_KEY_LEN 16
#define MT_CCM_NONCE_LEN 13
#define MT_CCM_TAG_LEN 16

/* ---- hashing and key derivation ---- */
void mt_crypto_sha256(mt_span in, uint8_t out[MT_SHA256_LEN]);

typedef struct { mbedtls_sha256_context c; } mt_sha256;
void mt_sha256_begin(mt_sha256 *s);
void mt_sha256_update(mt_sha256 *s, mt_span in);
void mt_sha256_finish(mt_sha256 *s, uint8_t out[MT_SHA256_LEN]); /* the context is released */
/* Digest of everything hashed so far; s keeps running. */
void mt_sha256_peek(const mt_sha256 *s, uint8_t out[MT_SHA256_LEN]);

mt_err mt_crypto_hmac_sha256(mt_span key, mt_span msg, uint8_t out[MT_SHA256_LEN]);
/* salt may be empty (len 0). */
mt_err mt_crypto_hkdf_sha256(mt_span salt, mt_span ikm, mt_span info, mt_buf okm);

/* ---- AES-128-CCM, 13-byte nonce, 16-byte tag ---- */
/* out.cap >= in.len + 16; writes ciphertext || tag and returns the length in *out_len. */
mt_err mt_crypto_ccm_encrypt(const uint8_t key[MT_CCM_KEY_LEN], const uint8_t nonce[MT_CCM_NONCE_LEN],
                             mt_span aad, mt_span in, mt_buf out, size_t *out_len);
/* in = ciphertext || tag; out.cap >= in.len - 16. MT_ERR_CRYPTO if the tag does not verify. */
mt_err mt_crypto_ccm_decrypt(const uint8_t key[MT_CCM_KEY_LEN], const uint8_t nonce[MT_CCM_NONCE_LEN],
                             mt_span aad, mt_span in, mt_buf out, size_t *out_len);

/* ---- DRBG ---- */
/* Fills out with len fresh entropy bytes; returns 0 on success (same contract as mbedtls). */
typedef int (*mt_entropy_fn)(void *ctx, uint8_t *out, size_t len);
typedef struct { mbedtls_ctr_drbg_context d; } mt_rng;
mt_err mt_rng_init(mt_rng *r, mt_entropy_fn entropy, void *ctx);
void mt_rng_free(mt_rng *r);
mt_err mt_rng_fill(mt_rng *r, uint8_t *out, size_t len);

/* ---- P-256: ECDH and ECDSA-SHA256 (rng is used for key generation and blinding) ---- */
mt_err mt_crypto_p256_keygen(mt_rng *r, uint8_t priv[MT_P256_SCALAR_LEN], uint8_t pub[MT_P256_POINT_LEN]);
mt_err mt_crypto_p256_ecdh(mt_rng *r, const uint8_t priv[MT_P256_SCALAR_LEN],
                           const uint8_t peer[MT_P256_POINT_LEN], uint8_t secret[MT_P256_SCALAR_LEN]);
mt_err mt_crypto_p256_sign(mt_rng *r, const uint8_t priv[MT_P256_SCALAR_LEN], mt_span msg,
                           uint8_t sig[MT_P256_SIG_LEN]);
mt_err mt_crypto_p256_verify(const uint8_t pub[MT_P256_POINT_LEN], mt_span msg,
                             const uint8_t sig[MT_P256_SIG_LEN]);
/* r||s <-> ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }; der_out needs MT_P256_SIG_DER_MAX bytes. */
size_t mt_crypto_p256_sig_to_der(const uint8_t sig[MT_P256_SIG_LEN], uint8_t der_out[MT_P256_SIG_DER_MAX]);
mt_err mt_crypto_p256_sig_from_der(mt_span der, uint8_t sig[MT_P256_SIG_LEN]);

/* ---- P-256 point / scalar primitives (SPAKE2+) ---- */
mt_err mt_crypto_p256_point_check(const uint8_t pt[MT_P256_POINT_LEN]); /* on curve, not infinity */
/* out = k * P; P == NULL means the generator G. */
mt_err mt_crypto_p256_point_mul(mt_rng *r, const uint8_t k[MT_P256_SCALAR_LEN],
                                const uint8_t *p /* 65 B or NULL */, uint8_t out[MT_P256_POINT_LEN]);
/* out = a*P + b*Q; p == NULL means the base point G. Safe for secret scalars: each product is a blinded,
 * constant-time multiplication (rng), only the final point addition is not. Scalars must be in [1, n-1].
 * MT_ERR_CRYPTO for a scalar out of range or a result at infinity. */
mt_err mt_crypto_p256_point_muladd(mt_rng *rng, const uint8_t a[MT_P256_SCALAR_LEN], const uint8_t *p /* 65 B or NULL */,
                                   const uint8_t b[MT_P256_SCALAR_LEN], const uint8_t q[MT_P256_POINT_LEN],
                                   uint8_t out[MT_P256_POINT_LEN]);
/* out = P + Q. */
mt_err mt_crypto_p256_point_add(const uint8_t p[MT_P256_POINT_LEN], const uint8_t q[MT_P256_POINT_LEN],
                                uint8_t out[MT_P256_POINT_LEN]);
/* out = (big-endian integer of any length) mod n. out may alias in when len == 32. */
mt_err mt_crypto_p256_scalar_reduce(mt_span in, uint8_t out[MT_P256_SCALAR_LEN]);
/* out = -s mod n (negation lets muladd subtract a point). */
mt_err mt_crypto_p256_scalar_neg(const uint8_t s[MT_P256_SCALAR_LEN], uint8_t out[MT_P256_SCALAR_LEN]);

/* out = a*b mod n (out may alias either input). */
mt_err mt_crypto_p256_scalar_mul(const uint8_t a[MT_P256_SCALAR_LEN], const uint8_t b[MT_P256_SCALAR_LEN],
                                 uint8_t out[MT_P256_SCALAR_LEN]);

#endif
