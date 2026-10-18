#include "fake.h"
#include "ota_flash.h"
#include "ota_state.h"

#include <string.h>

#include "lwip/sys.h"

uint8_t fake_flash[0xC000];
int fake_erases;
bool fake_trial_begun;
uint32_t fake_recv_ms;
static uint32_t now_ms = 0xFFFF0000u; /* wraps during the tests */
static const uint8_t* upload;
static size_t uploadLeft;

void fake_reset(uint32_t runningSerial) {
    memset(fake_flash, 0x5A, sizeof fake_flash); /* the old image in the idle slot */
    memcpy(fake_flash + FAKE_SLOT_A + OTA_SERIAL_OFFSET, &runningSerial, sizeof runningSerial);
    fake_erases = 0;
    fake_trial_begun = false;
    fake_recv_ms = 0;
}

u32_t sys_now(void) { return now_ms; }

void fake_upload(const uint8_t* data, size_t n) {
    upload = data;
    uploadLeft = n;
}

int recv(int sock, void* buf, size_t n, int flags) {
    (void) sock;
    (void) flags;
    if (n > uploadLeft) {
        n = uploadLeft;
    }
    if (n > 1000) {
        n = 1000; /* short reads, like TCP */
    }
    now_ms += fake_recv_ms;
    memcpy(buf, upload, n);
    upload += n;
    uploadLeft -= n;
    return (int) n;
}

void ota_flash_erase(uint32_t offset) {
    memset(fake_flash + (offset & ~(OTA_SECTOR - 1)), 0xFF, OTA_SECTOR);
    fake_erases++;
}

void ota_flash_write(uint32_t offset, const uint8_t* data, size_t n) {
    for (size_t i = 0; i < n; i++) {
        fake_flash[offset + i] &= data[i];
    }
}

void ota_flash_read(uint32_t offset, uint8_t* data, size_t n) {
    memcpy(data, fake_flash + offset, n);
}

uint32_t ota_running_slot(void) { return FAKE_SLOT_A; }
uint32_t ota_other_slot(uint32_t slot) { return slot == FAKE_SLOT_A ? FAKE_SLOT_B : FAKE_SLOT_A; }
uint32_t ota_slot_size(void) { return FAKE_SLOT_SIZE; }

uint32_t ota_slot_serial(uint32_t slot) {
    uint32_t serial;
    memcpy(&serial, fake_flash + slot + OTA_SERIAL_OFFSET, sizeof serial);
    return serial;
}

void ota_invalidate_slot(uint32_t slot) { memset(fake_flash + slot, 0, OTA_MARK_SIZE); }

ota_trial ota_state_read(void) { return (ota_trial) { .pending = fake_trial_begun }; }
void ota_state_begin(uint32_t slot) { (void) slot; fake_trial_begun = true; }
void ota_state_clear(void) { fake_trial_begun = false; }
