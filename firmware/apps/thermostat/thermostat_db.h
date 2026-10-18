// HAP services of the thermostat: Thermostat (primary) and a "Child Lock" switch.
#ifndef THERMOSTAT_DB_H
#define THERMOSTAT_DB_H

#include "HAP.h"

extern const HAPService thermostatService;
extern const HAPService childLockService;

/** Attributes in the two services: (service + 7 characteristics) + (service + 3). */
#define THERMOSTAT_DB_ATTRIBUTES ((size_t) 12)

/** Raises events on every dynamic characteristic (call when the model's view changed). */
void thermostat_db_raise_events(HAPAccessoryServerRef* server);

#endif
