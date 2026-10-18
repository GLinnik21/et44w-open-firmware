/* Bench-only OTA failure modes, compiled in only with `make OTA_TEST=<mode>` (after `make clean`):
 *   never_confirm  HAP runs but the trial is never confirmed -> rollback at the OTA_TRIAL_MS deadline
 *   fault          the CPU faults 20 s after boot, every boot -> rollback after OTA_TRIAL_BOOTS boots
 * A normal build has neither: ota_test_confirm_hook() is ota_confirm and ota_test_start() does nothing. */
#pragma once

#include "ota.h"

#if defined(OTA_TEST_never_confirm)
#define ota_test_confirm_hook NULL
#else
#define ota_test_confirm_hook ota_confirm
#endif

void ota_test_start(void);
