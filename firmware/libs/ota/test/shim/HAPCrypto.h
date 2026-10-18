/* Host test shim for the ADK's PAL/HAPCrypto.h: just what ota_receive.c and the vendored Ed25519 need. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ED25519_PUBLIC_KEY_BYTES 32
#define ED25519_BYTES            64
#define SHA512_BYTES             64

int HAP_ed25519_verify(const uint8_t sig[ED25519_BYTES], const uint8_t* m, size_t m_len,
                       const uint8_t pk[ED25519_PUBLIC_KEY_BYTES]);
