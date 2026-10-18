/* Lets the ADK's mbedtls 2.x crypto backend (PAL/Crypto/MbedTLS/HAPMbedTLS.c) build against mbedtls 3.x.
 * Force-included into ADK sources (homekit_adk_CFLAGS) so the vendor tree stays unmodified.
 *   - 3.x made struct fields private; HAPMbedTLS.c reads ecp_keypair .grp/.Q/.d directly.
 *   - 3.x dropped the *_ret suffix of the hash functions (they always return int now). */
#pragma once

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#define mbedtls_sha1_starts_ret    mbedtls_sha1_starts
#define mbedtls_sha1_update_ret    mbedtls_sha1_update
#define mbedtls_sha1_finish_ret    mbedtls_sha1_finish
#define mbedtls_sha256_starts_ret  mbedtls_sha256_starts
#define mbedtls_sha256_update_ret  mbedtls_sha256_update
#define mbedtls_sha256_finish_ret  mbedtls_sha256_finish
#define mbedtls_sha512_starts_ret  mbedtls_sha512_starts
#define mbedtls_sha512_update_ret  mbedtls_sha512_update
#define mbedtls_sha512_finish_ret  mbedtls_sha512_finish
