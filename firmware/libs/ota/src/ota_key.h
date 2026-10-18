/* Sanity check of the configured OTA public key. Pure C (host-tested in libs/ota/test).
 * A verifier that doesn't reject small-order keys lets forged signatures through under such a key (the
 * all-zero placeholder is one: y = 0, order 4), so refuse it regardless of the verifier. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* False for every encoding of a small-order point (sign bit ignored): the module then refuses all uploads. */
bool ota_key_usable(const uint8_t key[32]);
