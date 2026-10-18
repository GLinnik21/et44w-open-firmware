/* mbedtls 3.1.0 (from the SDK), crypto only, for the Matter stack (firmware and the host tests of the pure libs):
 *   P-256 ECDSA (certificates, CASE, attestation, CSR), ECDH and point arithmetic (CASE, SPAKE2+),
 *   AES-128-CCM (secure sessions), HKDF/HMAC-SHA-256, CTR-DRBG seeded by the caller.
 * Left out on purpose: PK, X.509 (matter-cert rebuilds the TBS and the CSR with its own forward DER
 * emitter, der.c, not mbedtls's back-to-front ASN.1 writer), PEM, ENTROPY_C (the port injects the SDK TRNG),
 * ECDSA_DETERMINISTIC, secp384r1. OTA's Ed25519 and SHA-512 come from Monocypher (libs/ed25519).
 * Selected for every user of the mbedtls lib via MBEDTLS_CONFIG_FILE (mbedtls_DEFS). Named so the SDK's own
 * mbedtls_config.h can't shadow it. */
#pragma once

#define MBEDTLS_HAVE_ASM               /* Cortex-M33 +dsp: UMAAL multiply-accumulate in bn_mul.h */
#define MBEDTLS_MPI_WINDOW_SIZE        2 /* RAM over speed */

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECP_WINDOW_SIZE        2 /* RAM over speed; revisit after on-device timings */
#define MBEDTLS_ECP_FIXED_POINT_OPTIM  0
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

#define MBEDTLS_MD_C
#define MBEDTLS_SHA224_C   /* mbedtls 3.1 requires it with SHA256_C */
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_SMALLER
#define MBEDTLS_HKDF_C

#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES      /* tables in flash, not 8 KiB of RAM */
#define MBEDTLS_AES_FEWER_TABLES
#define MBEDTLS_CIPHER_C            /* mbedtls 3.1 CCM goes through the cipher layer */
#define MBEDTLS_CCM_C
#define MBEDTLS_CTR_DRBG_C
