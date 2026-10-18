/* Pure range checks for the DCT flash guard (store_dct.c wraps dct_flash_write / dct_flash_erase with them).
 * lib_dct.a's dct_flash_erase(addr, len) erases ((len - 1) >> 12) + 1 sectors from addr, so len 0 would erase
 * 2^20 sectors (the whole flash, kv, ota_state and the bootloader included): it is refused, as is any span that
 * does not lie entirely in [base, base + size). */
#ifndef MTP_FLASH_GUARD_H
#define MTP_FLASH_GUARD_H

#include <stdbool.h>
#include <stdint.h>

#define MTP_SECTOR 0x1000u

/* [addr, addr + len) inside [base, base + size); len 0 is accepted as a no-op write at an address inside. */
static inline bool mtp_guard_write_ok(uint32_t addr, uint32_t len, uint32_t base, uint32_t size)
{
    return addr >= base && addr - base < size && len <= size - (addr - base);
}

/* What dct_flash_erase(addr, len) would erase lies inside [base, base + size). */
static inline bool mtp_guard_erase_ok(uint32_t addr, uint32_t len, uint32_t base, uint32_t size)
{
    uint64_t span;
    if (len == 0 || (addr & (MTP_SECTOR - 1))) return false;
    span = ((uint64_t)((len - 1u) >> 12) + 1u) * MTP_SECTOR;   /* the sectors the real function erases */
    return addr >= base && addr - base < size && span <= (uint64_t)(size - (addr - base));
}

#endif
