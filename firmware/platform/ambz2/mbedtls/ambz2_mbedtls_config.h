/* mbedtls 3.1.0 (from the SDK), crypto only: the base set (extended by ambz2_mbedtls_matter_config.h).
 *   Pair Setup:  SRP-3072 (bignum) + SHA-512, HKDF-SHA-512
 *   Pair Verify: X25519 (ECDH on Curve25519), ChaCha20-Poly1305
 *   Ed25519 comes with the ADK; AES-CTR, SHA-1 and PBKDF2 are used by other ADK helpers.
 * Selected for every user of the mbedtls lib via MBEDTLS_CONFIG_FILE (mbedtls_DEFS). */
#pragma once

#define MBEDTLS_HAVE_ASM            /* Cortex-M33 +dsp: UMAAL multiply-accumulate in bn_mul.h */
#define MBEDTLS_MPI_WINDOW_SIZE 6   /* faster SRP modular exponentiation, ~6 KiB more heap while it runs */
#define MBEDTLS_MPI_MAX_SIZE    512 /* 3072-bit SRP needs 384 bytes */

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECDH_C

#define MBEDTLS_MD_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA224_C   /* mbedtls 3.1 requires it with SHA256_C */
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_SMALLER
#define MBEDTLS_SHA512_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_PKCS5_C

#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES      /* tables in flash, not 8 KiB of RAM */
#define MBEDTLS_AES_FEWER_TABLES
#define MBEDTLS_CIPHER_MODE_CTR
