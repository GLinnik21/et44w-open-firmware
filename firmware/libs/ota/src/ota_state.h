/* Trial-boot record in the ota_state sector. Append-only between erases (bits only ever cleared), so
 * every step is a single program operation and survives a power cut:
 *   word 0  OTA_STATE_MAGIC        trial pending
 *   word 1  slot offset on trial
 *   word 2+ one word zeroed per boot of that slot
 * An erased sector means no trial. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool pending;
    uint32_t slot;
    uint32_t boots; /* boots of `slot` counted so far */
} ota_trial;

ota_trial ota_state_read(void);
void ota_state_begin(uint32_t slot); /* erase + record a new trial */
void ota_state_count_boot(void);    /* call while pending; no-op once the sector is full */
void ota_state_clear(void);          /* erase */
