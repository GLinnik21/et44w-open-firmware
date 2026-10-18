/* Receives one upload from a connected socket into the idle slot (wire format in ota.h). */
#pragma once

#include <stdint.h>

/* Returns NULL if the image is written, verified and armed (caller replies and resets), else a short
 * reason for the client. On failure the idle slot is left without a boot mark, so it never boots. */
const char* ota_receive(int sock, const uint8_t publicKey[32]);
