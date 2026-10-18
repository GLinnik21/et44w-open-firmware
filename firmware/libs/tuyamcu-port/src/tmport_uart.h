/* UART0 for the TuyaMCU port: RX IRQ drains into a stream buffer, TX is busy-wait. */
#ifndef TMPORT_UART_H
#define TMPORT_UART_H

#include <stddef.h>
#include <stdint.h>

#include "FreeRTOS.h"

/* Returns 0 on success. Starts at `baud`, 8N1. */
int tmport_uart_open(uint32_t baud);
void tmport_uart_set_baud(uint32_t baud);
void tmport_uart_write(const uint8_t *buf, size_t n);
/* Waits up to `ticks` for bytes; returns the count read (0 on timeout). */
size_t tmport_uart_read(uint8_t *buf, size_t max, TickType_t ticks);
/* Drops bytes received so far (used after a baud change). */
void tmport_uart_flush_rx(void);
/* RX bytes dropped so far because the stream buffer was full (the port task fell behind). */
uint32_t tmport_uart_dropped(void);

#endif
