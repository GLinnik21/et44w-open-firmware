#include "ota_flash.h"

#include <stdio.h>
#include <string.h>

#include "device_lock.h"
#include "flash_api.h"
#include "flash_map.h"
#include "sys_api.h"

// lib_soc_is: the bootloader's view of the slots (addresses are physical flash offsets).
extern void get_fw_info(uint32_t* targetFWaddr, uint32_t* currentFWaddr, uint32_t* fw1_sn, uint32_t* fw2_sn);

static flash_t flash;

void ota_flash_erase(uint32_t offset) {
    device_mutex_lock(RT_DEV_LOCK_FLASH);
    flash_erase_sector(&flash, offset);
    device_mutex_unlock(RT_DEV_LOCK_FLASH);
}

void ota_flash_write(uint32_t offset, const uint8_t* data, size_t n) {
    device_mutex_lock(RT_DEV_LOCK_FLASH);
    flash_stream_write(&flash, offset, (uint32_t) n, (uint8_t*) data);
    device_mutex_unlock(RT_DEV_LOCK_FLASH);
}

void ota_flash_read(uint32_t offset, uint8_t* data, size_t n) {
    device_mutex_lock(RT_DEV_LOCK_FLASH);
    flash_stream_read(&flash, offset, (uint32_t) n, data);
    device_mutex_unlock(RT_DEV_LOCK_FLASH);
}

uint32_t ota_running_slot(void) {
    uint32_t target, current, sn1, sn2;
    get_fw_info(&target, &current, &sn1, &sn2);
    return current == FLASH_ota1_OFFSET || current == FLASH_ota2_OFFSET ? current : 0;
}

uint32_t ota_other_slot(uint32_t slot) {
    return slot == FLASH_ota1_OFFSET ? FLASH_ota2_OFFSET : FLASH_ota1_OFFSET;
}

uint32_t ota_slot_size(void) {
    _Static_assert((uint32_t) FLASH_ota1_SIZE == (uint32_t) FLASH_ota2_SIZE, "OTA slots must be the same size");
    return FLASH_ota1_SIZE;
}

uint32_t ota_slot_serial(uint32_t slot) {
    uint32_t serial;
    ota_flash_read(slot + OTA_SERIAL_OFFSET, (uint8_t*) &serial, sizeof serial);
    return serial;
}

void ota_flash_print_info(void) {
    uint32_t target, current, sn1, sn2;
    get_fw_info(&target, &current, &sn1, &sn2);
    printf("ota: bootloader current 0x%lx target 0x%lx sn1 %lu sn2 %lu\n", (unsigned long) current,
           (unsigned long) target, (unsigned long) sn1, (unsigned long) sn2);
}

void ota_invalidate_slot(uint32_t slot) {
    static const uint8_t zeros[OTA_MARK_SIZE];
    ota_flash_write(slot, zeros, sizeof zeros);
}

void ota_reset(void) {
    sys_reset(); // disables fast boot, then resets through the watchdog
    for (;;) {
    }
}
