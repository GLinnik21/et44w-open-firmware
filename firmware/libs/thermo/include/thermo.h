/* Thermostat model between the TuyaMCU DPs of the ET-44W and the controller (Apple Home over Matter).
 * Pure: no I/O, no clock; the caller passes now_ms (monotonic, may wrap).
 * Not thread-safe; drive it from one task.
 *
 * Reports from the MCU go in with thermo_report(); controller writes go in with thermo_set_*(), which
 * record a pending value. While a value is pending, controller reads see the pending value and
 * non-matching reports are held back, so the Home app slider doesn't jump back to the stale value
 * the MCU echoes. A matching report, or THERMO_PENDING_MS without one, ends the hold.
 * thermo_take_writes() hands out the DP writes once (the caller debounces). */
#ifndef THERMO_H
#define THERMO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* DP ids (ET-44W thing model). */
enum {
    THERMO_DP_SWITCH = 1,
    THERMO_DP_MODE = 2,
    THERMO_DP_STATE = 3,
    THERMO_DP_SETPOINT = 16,
    THERMO_DP_CURRENT = 24,
    THERMO_DP_FAULT = 104
};

/* Target and current modes; matter-thermostat maps them to SystemMode / ThermostatRunningState. */
enum { THERMO_MODE_OFF = 0, THERMO_MODE_HEAT = 1, THERMO_MODE_AUTO = 3 };

#define THERMO_RAW_UNKNOWN 0xFFu  /* raw DP value not mapped yet */
#define THERMO_SET_MIN 50         /* tenths of a degree C */
#define THERMO_SET_MAX 400
#define THERMO_PENDING_MS 3000u

typedef struct {
    uint8_t mode_hold;     /* raw DP2 for manual; THERMO_RAW_UNKNOWN = mode writes disabled */
    uint8_t mode_smart;    /* raw DP2 for the weekly schedule; unknown = no Auto */
    uint8_t mode_holiday;  /* raw DP2 for holiday (shown as Auto, never written) */
    uint8_t state_heating; /* raw DP3 while the relay is on; unknown = guess from temperatures */
} thermo_cfg;

typedef enum { THERMO_W_BOOL, THERMO_W_VALUE, THERMO_W_ENUM } thermo_wtype;

typedef struct {
    uint8_t dp;
    uint8_t type; /* thermo_wtype */
    int32_t value;
} thermo_write;

#define THERMO_MAX_WRITES 4u

typedef struct {
    bool known;    /* reported at least once */
    bool pending;  /* written by a controller, not yet confirmed */
    bool dirty;    /* write not handed out yet */
    bool sent;     /* a write was handed out and its echo not seen: the MCU may still apply it */
    int32_t value; /* last report */
    int32_t want;  /* pending value */
    uint32_t since;
} thermo_slot;

enum { THERMO_S_SWITCH, THERMO_S_MODE, THERMO_S_STATE, THERMO_S_SETPOINT, THERMO_S_CURRENT,
       THERMO_S_FAULT, THERMO_S_COUNT };

typedef struct {
    thermo_cfg cfg;
    thermo_slot s[THERMO_S_COUNT];
} thermo;

void thermo_init(thermo *t, const thermo_cfg *cfg);

/* One DP report from the MCU. Returns true if a controller-visible value changed (raise events).
 * Unknown DPs are ignored. */
bool thermo_report(thermo *t, uint8_t dp, int32_t value, uint32_t now_ms);
/* True for the DPs thermo_report uses (THERMO_DP_*): callers queue only these to the model's task. */
bool thermo_dp_used(uint8_t dp);

/* Expires pending values. Returns true if a controller-visible value changed. Call >= every second. */
bool thermo_tick(thermo *t, uint32_t now_ms);

/* All of switch, mode, setpoint and current temperature have been reported. */
bool thermo_ready(const thermo *t);

/* Controller reads. Temperatures are tenths of a degree C. */
uint8_t thermo_target_state(const thermo *t);
uint8_t thermo_current_state(const thermo *t);
int32_t thermo_target_tenths(const thermo *t);
int32_t thermo_current_tenths(const thermo *t);
bool thermo_fault(const thermo *t);
bool thermo_auto_supported(const thermo *t);

/* Controller writes. Return false if the value isn't supported (nothing is changed). */
bool thermo_set_target_state(thermo *t, uint8_t mode, uint32_t now_ms);
bool thermo_set_target_c(thermo *t, float celsius, uint32_t now_ms); /* clamped, rounded to 0.5 */

/* DP writes not handed out yet, switch first. Returns the count (<= max) and clears them; the
 * pending hold restarts at now_ms so it covers the MCU's round trip. */
size_t thermo_take_writes(thermo *t, thermo_write *out, size_t max, uint32_t now_ms);
bool thermo_has_writes(const thermo *t);

#endif
