#include "boot_policy.h"

/* MT_BOOT_* values of mt_gendiag.h, repeated so this file needs no Matter headers (checked in boot.c). */
enum { BOOT_UNSPECIFIED = 0, BOOT_POWER_ON = 1, BOOT_HW_WATCHDOG = 4, BOOT_SW_RESET = 6 };

#define RAW_SOFTWARE 0x1u
#define RAW_WATCHDOG 0x2u

uint8_t mtp_boot_reason_of(uint32_t raw)
{
    if (raw == 0) return BOOT_POWER_ON;
    if (raw & RAW_WATCHDOG) return BOOT_HW_WATCHDOG;
    if (raw & RAW_SOFTWARE) return BOOT_SW_RESET;
    return BOOT_UNSPECIFIED;
}

uint8_t mtp_safe_on_boot(uint8_t count, uint32_t raw)
{
    if (raw == 0) return 0;
    if (raw & RAW_WATCHDOG) return count < UINT8_MAX ? (uint8_t)(count + 1) : count;
    return count;
}

uint32_t mtp_store_hold_ms(uint32_t raw) { return (raw & RAW_WATCHDOG) ? MTP_WDOG_HOLD_MS : 0; }
