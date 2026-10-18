// Measurement probe: starts the BLE stack and advertises Matter's BTP service (0xFFF6) for a window,
// then shuts it down and calls done(heap_ok) if not NULL: heap_ok = free heap came back to within 2 KiB of the
// pre-BT level (no big leak).
#pragma once
#include <stdbool.h>
void ble_probe_start(void (*done)(bool heap_ok));
