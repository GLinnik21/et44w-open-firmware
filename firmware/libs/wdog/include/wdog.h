/* Hardware watchdog with a feeder task just above idle. If any task hogs the CPU, the system hangs in
 * a fault handler, or interrupts stay off for WDOG_TIMEOUT_MS, the chip resets (reset reason
 * "watchdog"), which lets the OTA trial count a failed boot instead of hanging forever. A task that
 * blocks forever (deadlock, lost event) is not caught: the feeder keeps running. */
#pragma once

#define WDOG_TIMEOUT_MS 30000u /* longer than the slowest blocking work (SRP pair setup) */

/* Arms the watchdog and creates the feeder task; call before the scheduler starts. */
void wdog_start(void);
