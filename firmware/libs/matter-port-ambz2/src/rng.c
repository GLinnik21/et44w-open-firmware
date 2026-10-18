/* Entropy for the node's CTR-DRBG (mt_rng) and the DAC signer's DRBG: the SDK's crypto_random_generate. The chip
 * has no TRNG; the SDK derives the bytes from timer jitter, slowly, and the call is not reentrant, hence the
 * mutex. Only DRBG seeding and reseeding come here, never per-message randomness. */
#include "FreeRTOS.h"
#include "semphr.h"

#include "crypto_api.h"

#include "port.h"

static SemaphoreHandle_t lock;

bool mtp_rng_init(void)
{
    if (!lock) lock = xSemaphoreCreateMutex();
    return lock != NULL;
}

int mtp_entropy(void *ctx, uint8_t *out, size_t len)
{
    int r;
    (void)ctx;
    if (!lock || xSemaphoreTake(lock, portMAX_DELAY) != pdTRUE) return -1;
    r = crypto_random_generate(out, (uint32_t)len);
    xSemaphoreGive(lock);
    return r == 0 ? 0 : -1;
}
