#include "netlog_ring.h"

#include "cmsis.h"

static char ring[NETLOG_RING_SIZE];
static volatile uint32_t head;

// PRIMASK, not a FreeRTOS critical section: the writer also runs from ISRs and before the scheduler.
void netlog_ring_put(char c) {
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    ring[head & (NETLOG_RING_SIZE - 1)] = c;
    head++;
    __set_PRIMASK(primask);
}

uint32_t netlog_ring_head(void) {
    return head;
}

size_t netlog_ring_read(uint32_t* pos, char* buf, size_t n, uint32_t* lost) {
    uint32_t primask = __get_PRIMASK();
    __disable_irq();
    uint32_t h = head;
    if (h - *pos > NETLOG_RING_SIZE) {
        *lost += h - NETLOG_RING_SIZE - *pos;
        *pos = h - NETLOG_RING_SIZE;
    }
    size_t count = 0;
    while (count < n && *pos != h) {
        buf[count++] = ring[*pos & (NETLOG_RING_SIZE - 1)];
        (*pos)++;
    }
    __set_PRIMASK(primask);
    return count;
}
