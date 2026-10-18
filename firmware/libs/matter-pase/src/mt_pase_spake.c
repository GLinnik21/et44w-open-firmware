#include "mt_pase_spake.h"

#include <string.h>

#define SC MT_P256_SCALAR_LEN
#define PT MT_P256_POINT_LEN

/* RFC 9383 section 4: M and N for P-256, uncompressed. */
const uint8_t mt_spake_M[PT] = {
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99,
    0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f, 0x5f,
    0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b,
    0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20 };
const uint8_t mt_spake_N[PT] = {
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07,
    0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49, 0x07,
    0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b,
    0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7 };
mt_err mt_spake_verifier_points(mt_rng *rng, const uint8_t w0[SC], const uint8_t l[PT], const uint8_t pa[PT],
                                const uint8_t y[SC], uint8_t pb[PT], uint8_t z[PT], uint8_t v[PT])
{
    uint8_t yw0[SC], neg_yw0[SC];
    /* pA and L are checked (on the curve, not infinity) where muladd and mul read them. */
    mt_err e = mt_crypto_p256_point_muladd(rng, y, NULL, w0, mt_spake_N, pb);
    /* Z = y*(X - w0*M) = y*X + (-(y*w0 mod n))*M; muladd keeps the secret scalars on the blinded path. */
    if (e == MT_OK) e = mt_crypto_p256_scalar_mul(y, w0, yw0);
    if (e == MT_OK) e = mt_crypto_p256_scalar_neg(yw0, neg_yw0);
    if (e == MT_OK) e = mt_crypto_p256_point_muladd(rng, y, pa, neg_yw0, mt_spake_M, z);
    if (e == MT_OK) e = mt_crypto_p256_point_mul(rng, y, l, v);
    mt_wipe(yw0, sizeof yw0);
    mt_wipe(neg_yw0, sizeof neg_yw0);
    return e;
}

static void tt_add(mt_sha256 *s, const uint8_t *p, size_t n)
{
    uint8_t len[8];
    mt_put_le64(len, n);
    mt_sha256_update(s, mt_span_of(len, 8));
    mt_sha256_update(s, mt_span_of(p, n));
}

void mt_spake_transcript(mt_span context, mt_span id_p, mt_span id_v, const uint8_t pa[PT], const uint8_t pb[PT],
                         const uint8_t z[PT], const uint8_t v[PT], const uint8_t w0[SC], uint8_t out[MT_SHA256_LEN])
{
    mt_sha256 s;
    mt_sha256_begin(&s);
    tt_add(&s, context.p, context.len);
    tt_add(&s, id_p.p, id_p.len);
    tt_add(&s, id_v.p, id_v.len);
    tt_add(&s, mt_spake_M, PT);
    tt_add(&s, mt_spake_N, PT);
    tt_add(&s, pa, PT);
    tt_add(&s, pb, PT);
    tt_add(&s, z, PT);
    tt_add(&s, v, PT);
    tt_add(&s, w0, SC);
    mt_sha256_finish(&s, out);
}

mt_err mt_spake_confirm(const uint8_t tt_hash[MT_SHA256_LEN], const uint8_t pa[PT], const uint8_t pb[PT],
                        mt_spake_keys *k)
{
    static const char info[] = "ConfirmationKeys";
    uint8_t kc[32];
    memcpy(k->ke, tt_hash + 16, 16);
    mt_err e = mt_crypto_hkdf_sha256(mt_span_of(NULL, 0), mt_span_of(tt_hash, 16), mt_span_of(info, sizeof info - 1),
                                     mt_buf_of(kc, sizeof kc));
    if (e == MT_OK) e = mt_crypto_hmac_sha256(mt_span_of(kc, 16), mt_span_of(pb, PT), k->ca);
    if (e == MT_OK) e = mt_crypto_hmac_sha256(mt_span_of(kc + 16, 16), mt_span_of(pa, PT), k->cb);
    mt_wipe(kc, sizeof kc);
    return e;
}
