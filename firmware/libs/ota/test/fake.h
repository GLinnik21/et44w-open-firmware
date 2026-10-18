/* Fakes for the device side of ota_receive: a RAM flash with two slots, the trial record, and recv() from a
 * buffer. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FAKE_SLOT_A    0x4000u /* running */
#define FAKE_SLOT_B    0x8000u /* idle: receives the upload */
#define FAKE_SLOT_SIZE 0x4000u

extern uint8_t fake_flash[0xC000];
extern int fake_erases;        /* sectors erased */
extern bool fake_trial_begun;  /* ota_state_begin called and not cleared */
extern uint32_t fake_recv_ms;  /* sys_now() advance per recv(): a slow sender */

void fake_reset(uint32_t runningSerial);
void fake_upload(const uint8_t* data, size_t n); /* what recv() returns, then end of stream */
