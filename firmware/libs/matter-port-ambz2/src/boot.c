/* Reset reason and the safe-mode fault counter (policy in boot_policy.c). */
#include "boot_policy.h"
#include "port.h"

#include "reset_reason_api.h" /* hal_reset_reason_get_raw */

_Static_assert(MT_BOOT_POWER_ON == 1 && MT_BOOT_HW_WATCHDOG == 4 && MT_BOOT_SW_RESET == 6,
               "boot_policy.c repeats these values");

static uint32_t raw_reason;   /* 0 (power-on) unless captured */
static uint8_t safe_count;

void mtp_boot_capture(void) { raw_reason = hal_reset_reason_get_raw(); }

uint8_t mtp_boot_reason(void) { return mtp_boot_reason_of(raw_reason); }

uint32_t mtp_boot_hold_ms(void) { return mtp_store_hold_ms(raw_reason); }

bool mtp_boot_begin(void)
{
    uint8_t old = 0;
    size_t len = 0;
    mt_err e = mtp_store_get(MTP_MOD_BOOT, MTP_NAME_SAFE, mt_buf_of(&old, 1), &len);
    if (e != MT_OK || len != 1) old = 0;
    safe_count = mtp_safe_on_boot(old, raw_reason);
    if (safe_count != old || e == MT_ERR_NOT_FOUND)
        if (mtp_store_set(MTP_MOD_BOOT, MTP_NAME_SAFE, mt_span_of(&safe_count, 1)))
            MTP_LOG("SAFE write failed\r\n");
    MTP_LOG("boot: reset 0x%lx, fault count %u%s\r\n", (unsigned long)raw_reason, safe_count,
            mtp_safe_skip(safe_count) ? " -> SAFE MODE, node not started" : "");
    return mtp_safe_skip(safe_count);
}

void mtp_boot_stable(void)
{
    uint8_t next = mtp_safe_on_stable();
    if (next == safe_count) return;
    if (mtp_store_set(MTP_MOD_BOOT, MTP_NAME_SAFE, mt_span_of(&next, 1)) == MT_OK) safe_count = next;
}
