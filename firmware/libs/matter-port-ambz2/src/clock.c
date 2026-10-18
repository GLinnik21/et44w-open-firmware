/* Millisecond clock for the node: the FreeRTOS tick (configTICK_RATE_HZ 1000), wrapping at 2^32 like
 * mt_node_ports.now_ms expects. */
#include "FreeRTOS.h"
#include "task.h"

#include "port.h"

_Static_assert(configTICK_RATE_HZ == 1000, "one tick per millisecond");

uint32_t mtp_now_ms(void *ctx)
{
    (void)ctx;
    return (uint32_t)xTaskGetTickCount();
}
