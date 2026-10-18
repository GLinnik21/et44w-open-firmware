// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.
//
// Copyright 2020 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ChaCha20 DRBG with fast key erasure. The chip has no TRNG: the seed comes from the SDK's
// crypto_random_generate (timer jitter, slow, not reentrant), used only in HAPPlatformRandomNumberInit.
#include "HAPPlatform+Init.h"
#include <string.h>

#include "FreeRTOS.h"
#include "semphr.h"

#include "crypto_api.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/platform_util.h"

#include "HAPPlatformRandomNumber+Init.h"

#define KEY_SIZE   32
#define BLOCK_SIZE 256 // keystream per round: new key + up to BLOCK_SIZE - KEY_SIZE output bytes
#define SEED_ROUNDS 2  // independent crypto_random_generate calls mixed into the seed (XOR)

static SemaphoreHandle_t lock;
static uint8_t key[KEY_SIZE];

void HAPPlatformRandomNumberInit(void) {
    HAPPrecondition(!lock);

    uint8_t part[KEY_SIZE];
    memset(key, 0, sizeof key);
    for (int i = 0; i < SEED_ROUNDS; i++) {
        if (crypto_random_generate(part, sizeof part) != 0) {
            HAPFatalError();
        }
        for (size_t j = 0; j < KEY_SIZE; j++) {
            key[j] ^= part[j];
        }
    }
    mbedtls_platform_zeroize(part, sizeof part);

    lock = xSemaphoreCreateMutex();
    HAPAssert(lock);
}

void HAPPlatformRandomNumberFill(void* bytes, size_t numBytes) {
    HAPPrecondition(bytes);
    if (!lock) {
        HAPFatalError(); // not initialized
    }

    static const uint8_t nonce[12]; // the key changes every round, so a fixed nonce never repeats a stream
    uint8_t zeros[BLOCK_SIZE] = { 0 };
    uint8_t block[BLOCK_SIZE];
    uint8_t* out = bytes;

    xSemaphoreTake(lock, portMAX_DELAY);
    while (numBytes) {
        size_t n = numBytes < BLOCK_SIZE - KEY_SIZE ? numBytes : BLOCK_SIZE - KEY_SIZE;
        if (mbedtls_chacha20_crypt(key, nonce, 0, sizeof block, zeros, block) != 0) {
            HAPFatalError();
        }
        memcpy(key, block, KEY_SIZE); // erase the old key
        memcpy(out, block + KEY_SIZE, n);
        out += n;
        numBytes -= n;
    }
    xSemaphoreGive(lock);
    mbedtls_platform_zeroize(block, sizeof block);
}
