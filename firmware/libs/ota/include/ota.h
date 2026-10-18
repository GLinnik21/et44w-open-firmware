/* Over-the-air firmware update for AmebaZ2: signed images into the idle slot, trial boot, automatic
 * rollback.
 *
 * Upload (tools/ota_push.py): TCP to the OTA port, send
 *     "AOT2" | u32 LE image length | u32 LE image serial | SHA-512(image) | 64-byte Ed25519 signature | image
 * signature = Ed25519(key, "ambz2-ota-v2" | length | serial | SHA-512(image)), image = the packed slot image.
 * The module checks the signature and the serial before it erases anything, then streams the image into the
 * idle slot with its 32-byte boot mark held back, checks the image against the signed hash and a read-back
 * hash, records a trial, writes the boot mark last, replies one line ("OK ..." or "ERR ...") and reboots.
 * The v1 format ("AOTA", signature checked only after the slot was overwritten) is refused; firmware from
 * before v2 only speaks v1 (ota_push.py --legacy).
 * A placeholder or small-order public key (ota_key.h) makes the module refuse every upload, and fail its trial.
 *
 * Trial: the new image must call ota_confirm() within OTA_TRIAL_MS and within OTA_TRIAL_BOOTS boots, then
 * stay up OTA_CONFIRM_STABLE_MS more (a crash in that window still counts as a failed boot).
 * An image whose serial (packed in by tools/pack_image.py) isn't higher than the running one is refused.
 * Otherwise it zeroes its own boot mark and resets, and the bootloader falls back to the previous slot.
 * No new upload is accepted while a trial is pending. */
#pragma once

#include <stdint.h>

#define OTA_PORT        8267
#define OTA_TRIAL_MS    (5u * 60u * 1000u)
#define OTA_TRIAL_BOOTS 3u
#define OTA_CONFIRM_STABLE_MS (90u * 1000u) /* ota_confirm() takes effect after this much more uptime */
#define OTA_TRIAL_MAX_MS (30u * 60u * 1000u) /* ota_extend_trial() never moves the deadline past this uptime */

typedef struct {
    uint16_t port;
    const uint8_t* publicKey; /* 32-byte Ed25519 public key */
} ota_options;

/* Call early in main(), before the scheduler: counts trial boots and rolls back if they run out. */
void ota_boot_check(void);

/* Starts the upload server task; it also enforces the trial deadline. On a trial boot, rolls back at once if
 * the task can't be created or the key is unusable. */
void ota_start(const ota_options* options);

/* The running image is healthy: ends a pending trial. Safe to call any time, from any task. */
void ota_confirm(void);

/* The image can't be checked yet for a legitimate reason (e.g. offline on purpose while a BLE commissioning
 * window runs): the trial deadline becomes at least ms from now, capped at OTA_TRIAL_MAX_MS of uptime. Call it
 * repeatedly while the reason lasts. No effect without a pending trial. Any task. */
void ota_extend_trial(uint32_t ms);
