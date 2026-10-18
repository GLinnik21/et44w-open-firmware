/* Matter endpoint 1 for the ET-44W: device type Thermostat (0x0301), Identify (0x03) and Thermostat (0x201,
 * FeatureMap HEAT only), mapped onto libs/thermo. The thermo model stays the single source of truth; this
 * lib only translates and keeps a snapshot of what Matter has seen so it can mark exactly the changed
 * attributes dirty. Pure C11, no allocation, one task only (the Matter task).
 *
 * Checked against the Matter 1.3 data model files (connectedhomeip master, data_model/1.3/):
 *   device_types/Thermostat.xml (revision 3; Identify + Thermostat mandatory),
 *   clusters/Thermostat.xml (cluster revision 6), clusters/Identify.xml (cluster revision 4),
 * and the chip v1.3-branch thermostat-server.cpp for the status codes of the checks the XML leaves open.
 *
 * Thermostat attributes served (everything else is optional or needs another feature):
 *   0x0000 LocalTemperature (nullable: DP24 not reported yet, or a sensor fault), 0x0003/0x0004 AbsMin/Max
 *   HeatSetpointLimit (500/4000, F), 0x0012 OccupiedHeatingSetpoint (write: Operate), 0x0015/0x0016
 *   Min/MaxHeatSetpointLimit, 0x001B ControlSequenceOfOperation (HeatingOnly), 0x001C SystemMode (write:
 *   Manage), 0x0029 ThermostatRunningState (bit 0 = relay on). Command 0x00 SetpointRaiseLower.
 * Identify: IdentifyTime (write: Operate), IdentifyType, command 0x00 Identify (Manage).
 *
 * Endpoint 2 "Schedule" (only when thermo_auto_supported and not cfg.auto_mode): device type On/Off Plug-in Unit (0x010A) with On/Off
 * (0x0006, FeatureMap 0): OnOff = the MCU runs its weekly program (DP2 smart or holiday, see schedule.c). Apple
 * Home has no thermostat schedule control without a hub, so this switch is how Home toggles the program.
 *
 * Deviations (all documented in the .c files):
 *   - Endpoint 2 lacks the Identify and Groups clusters its device type requires (Apple doesn't use them).
 *   - With cfg.auto_mode: FeatureMap HEAT|AUTO without COOL, plus a read-only 0x0011 OccupiedCoolingSetpoint fixed
 *     at the heating maximum + MinSetpointDeadBand (4250), so cooling never applies. Apple Home reads it to derive
 *     the current heating/cooling state in Auto and fails without it.
 *   - Min/MaxHeatSetpointLimit are read-only (spec: writable by Manage); ControlSequenceOfOperation accepts
 *     only a write of HeatingOnly(2) and stays unchanged.
 *   - Identify TriggerEffect (optional) is not implemented.
 *   - Setpoints are rounded to 0.5 C by thermo, so a read after a write can differ from what was written. */
#ifndef MT_THERMOSTAT_H
#define MT_THERMOSTAT_H

#include "mt_dm.h"
#include "thermo.h"

#define MT_THERMOSTAT_ENDPOINT 1u
#define MT_SCHEDULE_ENDPOINT 2u
#define MT_PLUGIN_UNIT_DEVICE_TYPE 0x010Au
#define MT_PLUGIN_UNIT_DEVICE_REV 3u
#define MT_ONOFF_CLUSTER_ID 0x0006u
#define MT_ONOFF_REV 6u
#define MT_THERMOSTAT_DEVICE_TYPE 0x0301u
#define MT_THERMOSTAT_DEVICE_REV 3u
#define MT_IDENTIFY_CLUSTER_ID 0x0003u
#define MT_THERMOSTAT_CLUSTER_ID 0x0201u

#define MT_THERMOSTAT_REV 6u
#define MT_IDENTIFY_REV 4u
#define MT_THERMOSTAT_FEATURE_HEAT 0x1u
#define MT_THERMOSTAT_FEATURE_AUTO 0x20u

/* Setpoint limits in 0.01 C (= thermo's 5.0-40.0 C). */
#define MT_THERMOSTAT_MIN_SETPOINT (THERMO_SET_MIN * 10)
#define MT_THERMOSTAT_MAX_SETPOINT (THERMO_SET_MAX * 10)

enum { /* Thermostat attribute ids */
    MT_TSTAT_LOCAL_TEMPERATURE = 0x0000, MT_TSTAT_ABS_MIN_HEAT = 0x0003, MT_TSTAT_ABS_MAX_HEAT = 0x0004,
    MT_TSTAT_OCC_COOL_SETPOINT = 0x0011, MT_TSTAT_OCC_HEAT_SETPOINT = 0x0012, MT_TSTAT_MIN_HEAT = 0x0015, MT_TSTAT_MAX_HEAT = 0x0016, MT_TSTAT_MIN_DEADBAND = 0x0019,
    MT_TSTAT_CONTROL_SEQUENCE = 0x001B, MT_TSTAT_SYSTEM_MODE = 0x001C, MT_TSTAT_RUNNING_STATE = 0x0029
};
enum { MT_TSTAT_CMD_SETPOINT_RAISE_LOWER = 0x00 };
enum { MT_TSTAT_SEQ_HEATING_ONLY = 2 };                 /* ControlSequenceOfOperationEnum */
enum { MT_TSTAT_MODE_OFF = 0, MT_TSTAT_MODE_AUTO = 1, MT_TSTAT_MODE_HEAT = 4 }; /* SystemModeEnum */
enum { MT_TSTAT_RAISE_HEAT = 0, MT_TSTAT_RAISE_COOL = 1, MT_TSTAT_RAISE_BOTH = 2 }; /* SetpointRaiseLowerModeEnum */
enum { MT_TSTAT_RUNNING_HEAT = 0x0001 };                /* RelayStateBitmap */

enum { MT_ONOFF_ON_OFF = 0x0000 };
enum { MT_ONOFF_CMD_OFF = 0x00, MT_ONOFF_CMD_ON = 0x01, MT_ONOFF_CMD_TOGGLE = 0x02 };

enum { MT_IDENTIFY_TIME = 0x0000, MT_IDENTIFY_TYPE = 0x0001 };
enum { MT_IDENTIFY_CMD_IDENTIFY = 0x00 };
enum { MT_IDENTIFY_TYPE_NONE = 0, MT_IDENTIFY_TYPE_ACTUATOR = 5 }; /* IdentifyTypeEnum range */

typedef struct {
    thermo *model;                  /* owned by the app; fed with thermo_report() from the MCU */
    void *ctx;
    uint32_t (*now_ms)(void *ctx);  /* monotonic, may wrap; NULL = always 0 */
    /* Matter changed the model: the app drains thermo_take_writes() and sends the DPs (debounced).
     * May be NULL. */
    void (*on_write)(void *ctx);
    /* Identify started (true) or stopped (false), e.g. to blink the LED. May be NULL. */
    void (*on_identify)(void *ctx, bool active);
    uint8_t identify_type;          /* IdentifyTypeEnum: what the device does while identifying */
    /* SystemMode Auto = the weekly program (FeatureMap HEAT|AUTO, MinSetpointDeadBand), instead of endpoint 2.
     * Deviation: the spec's AUTO feature requires COOL; this unit can't cool. Needs thermo_auto_supported. */
    bool auto_mode;
} mt_thermostat_cfg;

typedef struct {                    /* what Matter has been told: diffed by mt_thermostat_sync */
    bool local_null;
    int16_t local, setpoint;
    uint8_t mode, running;
    bool schedule;                  /* endpoint 2 OnOff */
} mt_thermostat_snap;

typedef struct mt_thermostat {
    mt_thermostat_cfg cfg;          /* the instance must not move after init: the clusters point at it */
    mt_thermostat_snap snap;
    uint16_t identify_s;            /* IdentifyTime, seconds left */
    uint32_t identify_since;        /* now_ms of the last countdown step */
    mt_dm_cluster identify, thermostat, onoff;
    const mt_dm_cluster *clusters[3];
    const mt_dm_cluster *sched_clusters[2];
    mt_dm_devtype types[1], sched_types[1];
    mt_dm_endpoint eps[2];          /* endpoint 1, then endpoint 2 if n_eps == 2 */
    uint8_t n_eps;
} mt_thermostat;

/* MT_ERR_INVALID if model is NULL or identify_type is out of range. */
mt_err mt_thermostat_init(mt_thermostat *t, const mt_thermostat_cfg *cfg);

/* The endpoint-table entries for mt_node_cfg.extra_eps / n_extra_eps (the node copies them; `t` must outlive
 * the node): endpoint 1, plus endpoint 2 when the model supports the weekly program. */
const mt_dm_endpoint *mt_thermostat_endpoint(const mt_thermostat *t);
uint8_t mt_thermostat_endpoint_count(const mt_thermostat *t);

/* Call after thermo_report() (and after anything else that changed the model): marks every attribute whose
 * Matter-visible value differs from the snapshot dirty, once each (data version bump + subscription
 * report). Matter-side writes update the snapshot themselves, so they are not reported twice. */
void mt_thermostat_sync(mt_thermostat *t, mt_dm *dm);

/* Periodic work: thermo_tick() (a pending hold expiring snaps the value back), mt_thermostat_sync(), and the
 * IdentifyTime countdown (one dirty mark per second step; subscriptions still honour their min interval).
 * Returns ms until it should run again, UINT32_MAX when idle. Also call it after each Matter write/invoke
 * so the returned time stays right. */
uint32_t mt_thermostat_tick(mt_thermostat *t, mt_dm *dm);

#endif
