// Per-unit identity, selected with `make APP=apps/thermostat UNIT=<unit>` (default: example).
// Copy this folder to units/<your-unit>/ for each thermostat: every unit needs its own name and serial,
// and its own hap_setup_info.h (git-ignored, from tools/hap_setup.py).
#ifndef UNIT_H
#define UNIT_H

#define THERMOSTAT_NAME   "Floor Heating"
#define THERMOSTAT_SERIAL "000000000001"

// Local time zone (POSIX TZ) for the MCU's weekly schedule. Set your own, e.g. "CET-1CEST,M3.5.0,M10.5.0/3"
// (Central Europe), "EST5EDT,M3.2.0,M11.1.0" (US Eastern), "<+04>-4" (UTC+4, no DST).
#define THERMOSTAT_TZ "UTC0"

#endif
