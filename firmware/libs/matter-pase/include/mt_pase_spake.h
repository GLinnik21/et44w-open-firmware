/* SPAKE2+ (P256-SHA256-HKDF-HMAC, RFC 9383) as Matter uses it: the M/N points, the transcript hash,
 * and the verifier-side group math. Pure functions; the random scalar y is passed in so the RFC
 * vectors can be reproduced. Points are uncompressed X9.62 (65 B), scalars big-endian (32 B). */
#ifndef MT_PASE_SPAKE_H
#define MT_PASE_SPAKE_H

#include "mt_crypto.h"

extern const uint8_t mt_spake_M[MT_P256_POINT_LEN];
extern const uint8_t mt_spake_N[MT_P256_POINT_LEN];

/* What both sides derive from the transcript hash. */
typedef struct {
    uint8_t ke[16];            /* session secret */
    uint8_t ca[MT_SHA256_LEN]; /* HMAC(KcA, pB): the prover's confirmation */
    uint8_t cb[MT_SHA256_LEN]; /* HMAC(KcB, pA): the verifier's confirmation */
} mt_spake_keys;

/* Verifier math: Y = y*G + w0*N, Z = y*(X - w0*M), V = y*L. Rejects an off-curve or infinity X
 * (MT_ERR_CRYPTO). rng is used for blinding only. */
mt_err mt_spake_verifier_points(mt_rng *rng, const uint8_t w0[MT_P256_SCALAR_LEN], const uint8_t l[MT_P256_POINT_LEN],
                                const uint8_t pa[MT_P256_POINT_LEN], const uint8_t y[MT_P256_SCALAR_LEN],
                                uint8_t pb[MT_P256_POINT_LEN], uint8_t z[MT_P256_POINT_LEN],
                                uint8_t v[MT_P256_POINT_LEN]);

/* TT = len64le(x) || x for context, idP, idV, M, N, X, Y, Z, V, w0; out = SHA-256(TT). Matter uses
 * empty identities; the RFC vectors use others. */
void mt_spake_transcript(mt_span context, mt_span id_p, mt_span id_v, const uint8_t pa[MT_P256_POINT_LEN],
                         const uint8_t pb[MT_P256_POINT_LEN], const uint8_t z[MT_P256_POINT_LEN],
                         const uint8_t v[MT_P256_POINT_LEN], const uint8_t w0[MT_P256_SCALAR_LEN],
                         uint8_t out[MT_SHA256_LEN]);

/* Ka || Ke = tt_hash; KcA || KcB = HKDF(nil, Ka, "ConfirmationKeys"); cA, cB as above. */
mt_err mt_spake_confirm(const uint8_t tt_hash[MT_SHA256_LEN], const uint8_t pa[MT_P256_POINT_LEN],
                        const uint8_t pb[MT_P256_POINT_LEN], mt_spake_keys *k);

#endif
