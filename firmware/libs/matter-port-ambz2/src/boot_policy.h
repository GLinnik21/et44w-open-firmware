/* Boot policy of the port, pure: reset reason -> General Diagnostics BootReason, and the safe-mode fault counter
 * (a Matter crash loop must not take the recovery paths, OTA and netlog, down with it).
 *
 * Counter ("SAFE" in the boot module): +1 on every watchdog reset (libs/wdog turns faults and hangs into one),
 * 0 after a power-on reset, unchanged after a software reset (OTA install, our own reboots). The boot that sees
 * MTP_SAFE_FAULTS or more skips the Matter task. Once the node has run MTP_SAFE_STABLE_MS the counter goes back to
 * 0, so "3 faults within 5 minutes" is approximated as "3 watchdog resets with no 5-minute run in between". A
 * safe-mode boot clears it the same way: it stays without Matter until the next reset (an OTA install, a power
 * cycle), which tries Matter again. A crash loop thus ends in a boot that stays up, reachable for OTA. */
#ifndef MTP_BOOT_POLICY_H
#define MTP_BOOT_POLICY_H

#include <stdbool.h>
#include <stdint.h>

#define MTP_SAFE_FAULTS 3
#define MTP_SAFE_STABLE_MS (5u * 60u * 1000u)
/* After a watchdog reset the Matter task waits this long before it opens the store (DCT2) or runs any node code.
 * Wi-Fi, OTA and netlog start without it, so even a crash loop inside the store or the node leaves an OTA window
 * of this length (+ the 30 s watchdog) on every cycle. An upload takes about 10 s. */
#define MTP_WDOG_HOLD_MS (60u * 1000u)

/* raw: hal_reset_reason_get_raw() bits (0 = power-on, BIT0 software, BIT1 watchdog). */
uint8_t mtp_boot_reason_of(uint32_t raw);                 /* MT_BOOT_* */
uint8_t mtp_safe_on_boot(uint8_t count, uint32_t raw);    /* the counter for this boot */
uint32_t mtp_store_hold_ms(uint32_t raw);              /* 0, or MTP_WDOG_HOLD_MS after a watchdog reset */
static inline bool mtp_safe_skip(uint8_t count) { return count >= MTP_SAFE_FAULTS; }
static inline uint8_t mtp_safe_on_stable(void) { return 0; } /* after MTP_SAFE_STABLE_MS of uptime */

#endif
