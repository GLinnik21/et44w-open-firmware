// The TuyaMCU link of the Matter image: MCU reports -> libs/thermo -> Matter endpoint 1 (libs/matter-thermostat),
// and Matter writes -> thermo -> debounced DP writes. The thermo model and the endpoint belong to the Matter task;
// the TuyaMCU port task only queues reports here.
#ifndef THERMO_LINK_H
#define THERMO_LINK_H

#include <stdbool.h>
#include <stdint.h>

#include "mt_node.h"

// main(), before mtp_start(): initialises the model and the endpoint, starts the TuyaMCU port. False on failure;
// the Matter task functions below then do nothing.
bool thermo_link_start(void);
// Endpoints for mt_node_cfg.extra_eps / n_extra_eps (valid after thermo_link_start): 1 thermostat, 2 schedule.
const mt_dm_endpoint *thermo_link_endpoints(uint8_t *count);

// Matter task: the node is up (asks the MCU for every DP, so reports from before it are not lost).
void thermo_link_started(mt_node *n);
// Matter task, every loop: reports in, writes out, timers. Returns ms until it wants to run again.
uint32_t thermo_link_poll(mt_node *n);

// Any task: switch, mode, setpoint and temperature have all been reported (libs/thermo thermo_ready).
bool thermo_link_ready(void);

#endif
