/* Runs the TuyaMCU core on UART0 (PA_14 TX / PA_13 RX, 8N1) in its own task. Probes 9600 then
 * 115200 baud until the MCU answers. Callbacks run on the port task. */
#ifndef TUYAMCU_PORT_H
#define TUYAMCU_PORT_H

#include <stdbool.h>
#include <stdint.h>

#include "tuyamcu.h"

typedef struct {
    void (*on_event)(const tm_event *ev, void *ctx);
    /* Fill *t and return true; false = time not known yet. May be NULL (time never known). */
    bool (*get_time)(bool local, tm_time *t, void *ctx);
    void *ctx;
} tuyamcu_port_config;

/* Creates the UART and the task. Call once; config is copied. False if out of memory: the port is
 * then dead and the calls below return false. */
bool tuyamcu_port_start(const tuyamcu_port_config *config);

/* The calls below are thread-safe: they queue a command to the port task and never block. They
 * return false if the queue is full (the caller should resync later with tuyamcu_port_query_all). */

/* Applies a TM_NET_* status. */
bool tuyamcu_port_set_net_status(uint8_t status);

/* Writes one DP (type TM_DP_BOOL, TM_DP_VALUE or TM_DP_ENUM). The core's allowlist still applies:
 * denied writes are logged and dropped on the port task. */
bool tuyamcu_port_write(uint8_t dp, uint8_t type, int32_t value);

/* Asks the MCU to report all DPs. */
bool tuyamcu_port_query_all(void);

#endif
