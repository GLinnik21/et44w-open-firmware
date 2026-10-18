// Tees the console: re-registers the ROM stdio putc (both the secure and non-secure stub tables, as
// log_uart_port_init does) with a function that copies each byte into the ring, then calls the SDK's
// own UART putc. Every printf/rt_printf/putc path in ROM, the SDK and prebuilt libs ends there.
#include "netlog.h"
#include "netlog_ring.h"

#include <stdio.h>

#include "cmsis.h"
#include "hal_uart.h"
#include "reset_reason_api.h" // hal_reset_reason_get_raw/_clear
#include "stdio_port_func.h"

extern hal_uart_adapter_t log_uart;
extern void log_uart_wputc(void* adapter, char c); // lib_soc_is: UART putc, adds CR after LF
extern int log_uart_rgetc(void* adapter, char* c);

static void TeePutc(void* adapter, char c) {
    netlog_ring_put(c);
    log_uart_wputc(adapter, c);
}

// Raw bits per hal_sys_ctrl.h: 0 = power-on, BIT0 software, BIT1 watchdog, BIT2 JTAG.
static const char* ResetReasonName(uint32_t raw) {
    if (raw == 0) return "power-on";
    if (raw & 0x2u) return "watchdog";
    if (raw & 0x1u) return "software";
    return "other";
}

void netlog_init(void) {
    stdio_port_init_s(&log_uart, (stdio_putc_t) TeePutc, (stdio_getc_t) log_uart_rgetc);
    stdio_port_init(&log_uart, (stdio_putc_t) TeePutc, (stdio_getc_t) log_uart_rgetc);

    uint32_t raw = hal_reset_reason_get_raw();
    printf("\nnetlog: boot, reset reason %s (raw 0x%lx)\n", ResetReasonName(raw), (unsigned long) raw);
    hal_reset_reason_clear();
}
