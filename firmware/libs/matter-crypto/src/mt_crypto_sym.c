/* Hashing, MAC, KDF, AES-CCM and the DRBG. */
#include <string.h>

#include "mbedtls/ccm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mt_crypto.h"

static mt_err rc(int r) { return r == 0 ? MT_OK : MT_ERR_CRYPTO; }

static const mbedtls_md_info_t *sha256_info(void) { return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256); }

void mt_crypto_sha256(mt_span in, uint8_t out[MT_SHA256_LEN]) { mbedtls_sha256(in.p, in.len, out, 0); }

void mt_sha256_begin(mt_sha256 *s)
{
    mbedtls_sha256_init(&s->c);
    mbedtls_sha256_starts(&s->c, 0);
}

void mt_sha256_update(mt_sha256 *s, mt_span in) { mbedtls_sha256_update(&s->c, in.p, in.len); }

void mt_sha256_finish(mt_sha256 *s, uint8_t out[MT_SHA256_LEN])
{
    mbedtls_sha256_finish(&s->c, out);
    mbedtls_sha256_free(&s->c);
}

void mt_sha256_peek(const mt_sha256 *s, uint8_t out[MT_SHA256_LEN])
{
    mt_sha256 copy;
    mbedtls_sha256_init(&copy.c);
    mbedtls_sha256_clone(&copy.c, &s->c);
    mt_sha256_finish(&copy, out);
}

mt_err mt_crypto_hmac_sha256(mt_span key, mt_span msg, uint8_t out[MT_SHA256_LEN])
{
    return rc(mbedtls_md_hmac(sha256_info(), key.p, key.len, msg.p, msg.len, out));
}

mt_err mt_crypto_hkdf_sha256(mt_span salt, mt_span ikm, mt_span info, mt_buf okm)
{
    return rc(mbedtls_hkdf(sha256_info(), salt.p, salt.len, ikm.p, ikm.len, info.p, info.len, okm.p, okm.cap));
}

mt_err mt_crypto_ccm_encrypt(const uint8_t key[MT_CCM_KEY_LEN], const uint8_t nonce[MT_CCM_NONCE_LEN],
                             mt_span aad, mt_span in, mt_buf out, size_t *out_len)
{
    mbedtls_ccm_context c;
    int r;

    if (out.cap < in.len + MT_CCM_TAG_LEN) {
        return MT_ERR_BUFFER_TOO_SMALL;
    }
    mbedtls_ccm_init(&c);
    r = mbedtls_ccm_setkey(&c, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (r == 0) {
        r = mbedtls_ccm_encrypt_and_tag(&c, in.len, nonce, MT_CCM_NONCE_LEN, aad.p, aad.len, in.p, out.p,
                                        out.p + in.len, MT_CCM_TAG_LEN);
    }
    mbedtls_ccm_free(&c);
    *out_len = in.len + MT_CCM_TAG_LEN;
    return rc(r);
}

mt_err mt_crypto_ccm_decrypt(const uint8_t key[MT_CCM_KEY_LEN], const uint8_t nonce[MT_CCM_NONCE_LEN],
                             mt_span aad, mt_span in, mt_buf out, size_t *out_len)
{
    mbedtls_ccm_context c;
    size_t n;
    int r;

    if (in.len < MT_CCM_TAG_LEN) {
        return MT_ERR_INVALID;
    }
    n = in.len - MT_CCM_TAG_LEN;
    if (out.cap < n) {
        return MT_ERR_BUFFER_TOO_SMALL;
    }
    mbedtls_ccm_init(&c);
    r = mbedtls_ccm_setkey(&c, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (r == 0) {
        r = mbedtls_ccm_auth_decrypt(&c, n, nonce, MT_CCM_NONCE_LEN, aad.p, aad.len, in.p, out.p, in.p + n,
                                     MT_CCM_TAG_LEN);
    }
    mbedtls_ccm_free(&c);
    *out_len = n;
    return rc(r);
}

mt_err mt_rng_init(mt_rng *r, mt_entropy_fn entropy, void *ctx)
{
    mbedtls_ctr_drbg_init(&r->d);
    return rc(mbedtls_ctr_drbg_seed(&r->d, entropy, ctx, (const unsigned char *)"mt", 2));
}

void mt_rng_free(mt_rng *r) { mbedtls_ctr_drbg_free(&r->d); }

mt_err mt_rng_fill(mt_rng *r, uint8_t *out, size_t len) { return rc(mbedtls_ctr_drbg_random(&r->d, out, len)); }
