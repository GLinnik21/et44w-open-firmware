// Health of the Matter image: the S0 self-check that confirms an OTA trial, and
// memory lines in the network log while a commissioning is in progress. (netlog itself prints heap and every
// task's free stack, the "matter" task included, every 10 minutes.)
#ifndef HEALTH_H
#define HEALTH_H

#include <stdint.h>

#include "mt_node.h"

#define HEALTH_HEAP_FREE_MIN  (20u * 1024u) // free heap at the check
#define HEALTH_HEAP_EVER_MIN  (10u * 1024u) // lowest free heap since boot
#define HEALTH_THERMO_MS      60000u        // the MCU must have reported by then
#define HEALTH_NET_MS         180000u       // IP, UDP 5540 and the node by then, counted from boot or from the end of an
                                            // offline BLE window (leaves the trial >= 2 min to confirm)
#define HEALTH_COMMISSION_LOG_MS 5000u

// main(): creates the self-check task. It confirms the OTA trial (libs/ota-test hook) once IP is up, UDP 5540 is
// bound, the node runs, thermo is ready, BLE is not mid-start (uncommissioned: the stack is up, ~31 KiB), the OTA
// listener answers on loopback and the heap is within limits (the thresholds hold with BLE up);
// otherwise it never confirms and a trial rolls back. Safe mode (node skipped) therefore never confirms.
// Never without IP: while an uncommissioned unit is offline on purpose for its BLE window it keeps the trial open
// (ota_extend_trial) instead, and must then get IP (commissioning or the rescue network) within HEALTH_NET_MS.
void health_start(void);
// Wi-Fi task: an IPv4 address was obtained.
void health_on_ip(void);
// Matter task, every loop: heap / Matter task stack every HEALTH_COMMISSION_LOG_MS while commissioning (fail-safe
// armed, a handshake or a PASE session). Returns ms until it wants to run again.
uint32_t health_poll(mt_node *n);

#endif
