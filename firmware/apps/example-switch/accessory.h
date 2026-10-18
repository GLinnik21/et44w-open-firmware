// The HomeKit accessory (category Switch) and its HAP task configuration.
#ifndef ACCESSORY_H
#define ACCESSORY_H

#include "hap_app.h"

const hap_app_config* accessory_config(void (*onRunning)(void));

#endif
