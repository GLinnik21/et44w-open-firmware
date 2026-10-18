/* Phase 3 probe: runs the TuyaMCU link read-only (heartbeat, product info, status, DP query; no DP
 * writes) and logs every event, so the MCU's protocol can be read from the network log. */
#pragma once

void mcu_probe_start(void);
