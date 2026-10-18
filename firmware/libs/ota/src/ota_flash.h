/* Flash access for OTA: physical offsets, each call serialised with other flash users
 * (RT_DEV_LOCK_FLASH). Slots and their 32-byte boot mark (the bootloader's per-slot OTA signature). */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define OTA_SECTOR    0x1000u
#define OTA_MARK_SIZE 32u

void ota_flash_erase(uint32_t offset);                                 /* one 4 KiB sector */
void ota_flash_write(uint32_t offset, const uint8_t* data, size_t n);  /* program (bits 1 -> 0 only) */
void ota_flash_read(uint32_t offset, uint8_t* data, size_t n);

/* Offset of the slot the running image booted from (FLASH_ota1/ota2_OFFSET), or 0 if unknown. */
uint32_t ota_running_slot(void);
uint32_t ota_other_slot(uint32_t slot);
uint32_t ota_slot_size(void);

/* Offset of the image serial in a slot (and in an image); the bootloader boots the valid slot with the
 * higher one. ota_slot_serial reads it from flash. */
#define OTA_SERIAL_OFFSET 0xF4u
uint32_t ota_slot_serial(uint32_t slot);

/* Prints the bootloader's view (current/target slot, both serials) to the console. */
void ota_flash_print_info(void);

/* Zeroes the slot's boot mark: no erase needed, so a power cut can't leave it half-done. */
void ota_invalidate_slot(uint32_t slot);

/* Disables fast boot (so the bootloader re-selects the slot) and resets. */
void ota_reset(void) __attribute__((noreturn));
