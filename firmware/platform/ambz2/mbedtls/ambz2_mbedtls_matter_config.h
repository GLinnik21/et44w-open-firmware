/* mbedtls 3.1.0 config for the Matter stack (MATTER=1 builds and the host tests of the pure libs).
 * The HAP config plus what Matter needs on top:
 *   P-256 ECDSA (certificates, CASE, attestation, CSR), ECDH and point arithmetic (CASE, SPAKE2+),
 *   AES-128-CCM (secure sessions), HKDF/HMAC-SHA-256, CTR-DRBG seeded by the caller.
 * Left out on purpose: PK, X.509 (matter-cert rebuilds the TBS and the CSR with its own forward DER
 * emitter, der.c, not mbedtls's back-to-front ASN.1 writer), PEM, ENTROPY_C (the port injects the SDK TRNG),
 * ECDSA_DETERMINISTIC, secp384r1. */
#pragma once

#include "ambz2_mbedtls_config.h"

#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECP_WINDOW_SIZE        2 /* RAM over speed; revisit after on-device timings */
#define MBEDTLS_ECP_FIXED_POINT_OPTIM  0
#undef  MBEDTLS_MPI_WINDOW_SIZE
#define MBEDTLS_MPI_WINDOW_SIZE        2 /* HAP's 6 only speeds up SRP-3072, which Matter doesn't use */

#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_ECDSA_C

#define MBEDTLS_CIPHER_C           /* mbedtls 3.1 CCM goes through the cipher layer */
#define MBEDTLS_CCM_C
#define MBEDTLS_CTR_DRBG_C
