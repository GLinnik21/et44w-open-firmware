// Product constants of the Matter ET-44W image. Per-unit data: units/<UNIT>/matter_unit.h (Matter setup) and the
// HAP app's units/<UNIT>/unit.h (THERMOSTAT_NAME, shared so both firmwares call a unit the same).
#ifndef MATTER_CONFIG_H
#define MATTER_CONFIG_H

#define TM_VENDOR_NAME      "Warmee"
#define TM_PRODUCT_NAME     "ET-44W"
#define TM_HW_VERSION       1
#define TM_HW_VERSION_STR   "ET-44W.AX V3.0"
// Basic Information SoftwareVersion: bump with every image that changes the data model (controllers cache it).
#define TM_SW_VERSION       5
#define TM_SW_VERSION_STR   "0.5.0"

// Raw DP values of the ET-44W (same as apps/thermostat/config.h THERMOSTAT_THERMO_CFG).
#define TM_THERMO_CFG \
    { .mode_hold = 2, .mode_smart = 1, .mode_holiday = 0, .state_heating = 1 }

// BLE part of the boot commissioning window (spec 5.4.2.6: at most 15 min). Debug builds shorten it so a failed
// attempt's log is readable sooner (the device rejoins the rescue network when it ends): make BLE_WINDOW_S=180.
#ifndef BLE_WINDOW_S
#define BLE_WINDOW_S        (15 * 60)
#endif

// Thermostat Auto mode (= the weekly schedule) in Home's mode menu. Off: Off/Heat only (-DTM_AUTO_MODE=0).
#ifndef TM_AUTO_MODE
#define TM_AUTO_MODE 1
#endif

#endif
