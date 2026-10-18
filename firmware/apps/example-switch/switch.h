// Switch service: one On characteristic. State lives in RAM and is persisted in the KVS app domain.
#ifndef SWITCH_H
#define SWITCH_H

#include "HAP.h"

extern const HAPService switchService;

/** Attributes in switchService: the service + signature, name, on. */
#define SWITCH_ATTRIBUTES ((size_t) 4)

/** Loads the persisted state. Call from the HAP task before the accessory server starts. */
void switch_init(HAPAccessoryServerRef* server, HAPPlatformKeyValueStoreRef keyValueStore);

#endif
