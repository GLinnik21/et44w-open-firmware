// References every mbedtls function the Matter stack plans to use and checks that they
// work together: SHA-256, HMAC, HKDF, CCM, CTR-DRBG, P-256 keygen / ECDH / ECDSA, the point arithmetic
// SPAKE2+ needs, and the ASN.1 writer matter-cert uses. The DRBG is seeded from a fixed buffer: this
// is a size and timing probe, not a secure use.
#include <string.h>

#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ccm.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

#include "crypto_link.h"

volatile int crypto_link_enable;

static int fixed_entropy(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    for (size_t i = 0; i < len; i++) {
        out[i] = (unsigned char)(i * 7 + 1);
    }
    return 0;
}

static int sym(void)
{
    uint8_t k[16] = { 1 }, nonce[13] = { 2 }, aad[8] = { 3 }, pt[32] = { 4 }, ct[32], tag[16], out[32], h[32];
    mbedtls_ccm_context ccm;
    int bad = 0;

    bad |= mbedtls_sha256(pt, sizeof pt, h, 0);
    bad |= mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), k, sizeof k, pt, sizeof pt, h);
    bad |= mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), k, sizeof k, pt, sizeof pt, aad,
                        sizeof aad, out, sizeof out);
    mbedtls_ccm_init(&ccm);
    bad |= mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, k, 128);
    bad |= mbedtls_ccm_encrypt_and_tag(&ccm, sizeof pt, nonce, sizeof nonce, aad, sizeof aad, pt, ct, tag, sizeof tag);
    bad |= mbedtls_ccm_auth_decrypt(&ccm, sizeof ct, nonce, sizeof nonce, aad, sizeof aad, ct, out, tag, sizeof tag);
    bad |= memcmp(pt, out, sizeof pt);
    mbedtls_ccm_free(&ccm);
    return bad != 0;
}

static int asn1(void)
{
    unsigned char buf[64], *p = buf + sizeof buf;
    unsigned char *rd;
    size_t len = 0, rl;
    mbedtls_mpi r;
    int bad = 0, n;

    mbedtls_mpi_init(&r);
    bad |= mbedtls_mpi_lset(&r, 0x1234);
    n = mbedtls_asn1_write_mpi(&p, buf, &r);
    bad |= n < 0;
    len += n > 0 ? n : 0;
    n = mbedtls_asn1_write_len(&p, buf, len);
    len += n > 0 ? n : 0;
    n = mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    len += n > 0 ? n : 0;
    rd = p;
    bad |= mbedtls_asn1_get_tag(&rd, buf + sizeof buf, &rl, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    bad |= mbedtls_asn1_get_mpi(&rd, buf + sizeof buf, &r);
    mbedtls_mpi_free(&r);
    return bad != 0;
}

// P-256 keygen, ECDH, ECDSA sign / verify, and SPAKE2+'s W0*M + x*G style arithmetic (muladd, mul,
// point read / write, scalar mod n).
static int ec(mbedtls_ctr_drbg_context *drbg)
{
    mbedtls_ecp_group g;
    mbedtls_ecp_point q1, q2, r;
    mbedtls_mpi d1, d2, s, rr, ss;
    uint8_t pt[65], hash[32] = { 9 };
    size_t olen;
    int bad = 0;

    mbedtls_ecp_group_init(&g);
    mbedtls_ecp_point_init(&q1);
    mbedtls_ecp_point_init(&q2);
    mbedtls_ecp_point_init(&r);
    mbedtls_mpi_init(&d1);
    mbedtls_mpi_init(&d2);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&rr);
    mbedtls_mpi_init(&ss);

    bad |= mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1);
    bad |= mbedtls_ecp_gen_keypair(&g, &d1, &q1, mbedtls_ctr_drbg_random, drbg);
    bad |= mbedtls_ecp_gen_keypair(&g, &d2, &q2, mbedtls_ctr_drbg_random, drbg);
    bad |= mbedtls_ecp_check_pubkey(&g, &q1);
    bad |= mbedtls_ecdh_compute_shared(&g, &s, &q2, &d1, mbedtls_ctr_drbg_random, drbg);

    bad |= mbedtls_ecdsa_sign(&g, &rr, &ss, &d1, hash, sizeof hash, mbedtls_ctr_drbg_random, drbg);
    bad |= mbedtls_ecdsa_verify(&g, hash, sizeof hash, &q1, &rr, &ss);

    bad |= mbedtls_ecp_mul(&g, &r, &d1, &q2, mbedtls_ctr_drbg_random, drbg);
    bad |= mbedtls_ecp_muladd(&g, &r, &d1, &q1, &d2, &q2);
    bad |= mbedtls_ecp_point_write_binary(&g, &r, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pt, sizeof pt);
    bad |= mbedtls_ecp_point_read_binary(&g, &q1, pt, olen);
    bad |= mbedtls_ecp_is_zero(&r);
    bad |= mbedtls_mpi_mod_mpi(&s, &d1, &g.N);
    bad |= mbedtls_mpi_read_binary(&s, hash, sizeof hash);
    bad |= mbedtls_mpi_write_binary(&s, hash, sizeof hash);

    mbedtls_mpi_free(&ss);
    mbedtls_mpi_free(&rr);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&d2);
    mbedtls_mpi_free(&d1);
    mbedtls_ecp_point_free(&r);
    mbedtls_ecp_point_free(&q2);
    mbedtls_ecp_point_free(&q1);
    mbedtls_ecp_group_free(&g);
    return bad != 0;
}

int crypto_link_run(void)
{
    mbedtls_ctr_drbg_context drbg;
    int bad;

    mbedtls_ctr_drbg_init(&drbg);
    bad = mbedtls_ctr_drbg_seed(&drbg, fixed_entropy, NULL, (const unsigned char *)"mt", 2) != 0;
    bad += sym();
    bad += asn1();
    bad += ec(&drbg);
    mbedtls_ctr_drbg_free(&drbg);
    return bad;
}

void crypto_link_keep(void)
{
    if (crypto_link_enable) {
        crypto_link_run();
        (void)libs_link_keep();
    }
}
