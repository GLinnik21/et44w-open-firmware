#include "ota_state.h"
#include "ota_flash.h"

#include "flash_map.h"

#define OTA_STATE_MAGIC 0x3141544Fu /* "OTA1" */
#define MAX_WORDS       64u         /* scanned; far more than OTA_TRIAL_BOOTS */

static uint32_t ReadWord(uint32_t index) {
    uint32_t w;
    ota_flash_read(FLASH_ota_state_OFFSET + 4u * index, (uint8_t*) &w, sizeof w);
    return w;
}

static void ZeroWord(uint32_t index) {
    static const uint32_t zero = 0;
    ota_flash_write(FLASH_ota_state_OFFSET + 4u * index, (const uint8_t*) &zero, sizeof zero);
}

ota_trial ota_state_read(void) {
    ota_trial t = { 0 };
    if (ReadWord(0) != OTA_STATE_MAGIC) {
        return t;
    }
    t.pending = true;
    t.slot = ReadWord(1);
    for (uint32_t i = 2; i < MAX_WORDS && ReadWord(i) == 0; i++) {
        t.boots++;
    }
    return t;
}

void ota_state_begin(uint32_t slot) {
    ota_state_clear();
    const uint32_t record[2] = { OTA_STATE_MAGIC, slot };
    ota_flash_write(FLASH_ota_state_OFFSET, (const uint8_t*) record, sizeof record);
}

void ota_state_count_boot(void) {
    for (uint32_t i = 2; i < MAX_WORDS; i++) {
        if (ReadWord(i) != 0) {
            ZeroWord(i);
            return;
        }
    }
}

void ota_state_clear(void) {
    ota_flash_erase(FLASH_ota_state_OFFSET);
}
