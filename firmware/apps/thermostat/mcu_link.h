// The TuyaMCU link: starts the UART port and routes its events (DP reports to the thermostat and the
// DP cache, time requests to the clock). Logs product info and Wi-Fi reset requests.
#ifndef MCU_LINK_H
#define MCU_LINK_H

#include <stdbool.h>

// False if the port couldn't start (out of memory): the thermostat then never gets a report.
bool mcu_link_start(void);

#endif
