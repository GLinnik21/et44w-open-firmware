/* The firmware's Ed25519 verify (vendored ADK sources, as HAPMbedTLS.c builds them) on the host mbedtls. */
#include "HAPCrypto.h"
#include "mbedtls/sha512.h"

static void sha512_init(mbedtls_sha512_context* ctx) {
    mbedtls_sha512_init(ctx);
    mbedtls_sha512_starts(ctx, 0);
}
static void sha512_update(mbedtls_sha512_context* ctx, const uint8_t* data, size_t size) {
    mbedtls_sha512_update(ctx, data, size);
}
static void sha512_final(mbedtls_sha512_context* ctx, uint8_t md[SHA512_BYTES]) {
    mbedtls_sha512_finish(ctx, md);
    mbedtls_sha512_free(ctx);
}

static void HAP_sha512(uint8_t md[SHA512_BYTES], const uint8_t* data, size_t size) { /* for ed25519_sign.c */
    mbedtls_sha512(data, size, md, 0);
}

#include "curve25519_mehdi.c"
#include "curve25519_utils.c"
#include "curve25519_order.c"
#include "ed25519_sign.c" /* also defines constants and point ops the verifier uses */
#include "ed25519_verify.c"

int HAP_ed25519_verify(const uint8_t sig[ED25519_BYTES], const uint8_t* m, size_t m_len,
                       const uint8_t pk[ED25519_PUBLIC_KEY_BYTES]) {
    return ed25519_VerifySignature(sig, pk, m, m_len) == 1 ? 0 : -1;
}
