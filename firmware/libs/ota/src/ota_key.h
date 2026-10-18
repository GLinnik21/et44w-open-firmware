/* Sanity check of the configured OTA public key. Pure C (host-tested in libs/ota/test).
 * The ADK's Ed25519 verifier rejects neither small-order keys nor S >= L, so under a small-order key (the
 * all-zero placeholder is one: y = 0, order 4) a forged signature verifies about one try in four. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* False for every encoding of a small-order point (sign bit ignored): the module then refuses all uploads. */
bool ota_key_usable(const uint8_t key[32]);
