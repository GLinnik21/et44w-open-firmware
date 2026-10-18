#include "tmport_uart.h"

#include "serial_api.h"
#include "stream_buffer.h"
#include "task.h"

#define RX_BUF_BYTES 512

static serial_t s_uart;
static StreamBufferHandle_t s_rx;
static volatile uint32_t s_dropped; /* bytes lost to a full stream buffer */

/* ISR: only move bytes into the stream buffer. */
static void RxIrqHandler(uint32_t id, SerialIrq event) {
    (void) id;
    if (event != RxIrq) {
        return;
    }
    BaseType_t woken = pdFALSE;
    while (serial_readable(&s_uart)) {
        uint8_t b = (uint8_t) serial_getc(&s_uart);
        if (xStreamBufferSendFromISR(s_rx, &b, 1, &woken) == 0) {
            s_dropped++;
        }
    }
    portYIELD_FROM_ISR(woken);
}

int tmport_uart_open(uint32_t baud) {
    s_rx = xStreamBufferCreate(RX_BUF_BYTES, 1);
    if (s_rx == NULL) {
        return -1;
    }
    serial_init(&s_uart, PA_14, PA_13);
    serial_baud(&s_uart, (int) baud);
    serial_format(&s_uart, 8, ParityNone, 1);
    serial_irq_handler(&s_uart, RxIrqHandler, 0);
    serial_irq_set(&s_uart, RxIrq, 1);
    return 0;
}

void tmport_uart_set_baud(uint32_t baud) {
    serial_baud(&s_uart, (int) baud);
}

void tmport_uart_write(const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        serial_putc(&s_uart, buf[i]);
    }
}

size_t tmport_uart_read(uint8_t *buf, size_t max, TickType_t ticks) {
    return xStreamBufferReceive(s_rx, buf, max, ticks);
}

void tmport_uart_flush_rx(void) {
    xStreamBufferReset(s_rx);
}

uint32_t tmport_uart_dropped(void) {
    return s_dropped;
}
