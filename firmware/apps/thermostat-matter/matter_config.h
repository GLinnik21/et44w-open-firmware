// Product constants of the Matter ET-44W image. Per-unit data: units/<UNIT>/matter_unit.h (Matter setup) and
// units/<UNIT>/unit.h (THERMOSTAT_NAME).
#ifndef MATTER_CONFIG_H
#define MATTER_CONFIG_H

#define TM_VENDOR_NAME      "Warmee"
#define TM_PRODUCT_NAME     "ET-44W"
#define TM_HW_VERSION       1
#define TM_HW_VERSION_STR   "ET-44W.AX V3.0"
// Basic Information SoftwareVersion: bump with every image that changes the data model (controllers cache it).
#define TM_SW_VERSION       5
#define TM_SW_VERSION_STR   "0.5.0"

// Local time zone (POSIX TZ) for the MCU's weekly schedule (clock.c). Set your own, e.g.
// "CET-1CEST,M3.5.0,M10.5.0/3" (Central Europe), "EST5EDT,M3.2.0,M11.1.0" (US Eastern), "<+04>-4" (UTC+4, no DST).
#define TM_TZ "UTC0"

// Second DNS server, tried when the router's (from DHCP) doesn't answer, e.g. because an IoT VLAN
// firewall also blocks the router's own DNS.
#define TM_DNS_FALLBACK "1.1.1.1"

// Raw DP values of the ET-44W, from the Tuya thing model's enum order (mode: holiday, smart, hold; work_state:
// warming, heating), matching what the MCU reports.
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
