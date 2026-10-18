// Product constants for the ET-44W floor thermostat app.
#ifndef CONFIG_H
#define CONFIG_H

#include "unit.h" // per-unit name and serial: units/<UNIT>/unit.h

// Local time zone (POSIX TZ) for the MCU's weekly schedule: set per unit in units/<UNIT>/unit.h.
#ifndef THERMOSTAT_TZ
#define THERMOSTAT_TZ "UTC0"
#endif

// Second DNS server, tried when the router's (from DHCP) doesn't answer, e.g. because an IoT VLAN
// firewall also blocks the router's own DNS.
#define THERMOSTAT_DNS_FALLBACK "1.1.1.1"

// Raw DP values, from the Tuya thing model's enum order (mode: holiday, smart, hold;
// work_state: warming, heating) and matching what the MCU reports.
#define THERMOSTAT_THERMO_CFG \
    { .mode_hold = 2, .mode_smart = 1, .mode_holiday = 0, .state_heating = 1 }

#define THERMOSTAT_MANUFACTURER "Warmee"
#define THERMOSTAT_MODEL        "ET-44W"
#define THERMOSTAT_FIRMWARE     "1.0.3"

#endif
