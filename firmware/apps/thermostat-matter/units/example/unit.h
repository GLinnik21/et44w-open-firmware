// Per-unit identity, selected with `make UNIT=<unit>` (default: example).
// Copy this folder to units/<your-unit>/ for each thermostat: every unit needs its own name and serial, and its own
// matter_unit.h (git-ignored, from the matter-unit target; see lib.mk).
#ifndef UNIT_H
#define UNIT_H

#define THERMOSTAT_NAME   "Floor Heating"
#define THERMOSTAT_SERIAL "000000000001"

#endif
