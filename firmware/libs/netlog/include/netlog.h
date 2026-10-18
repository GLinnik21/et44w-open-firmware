/* Network log: every byte printed on the log UART is also kept in a RAM ring buffer and served to one
 * TCP client (read-only). A client gets the buffered history first (boot log included), then live output.
 *   nc <module-ip> 2323
 * Nothing is ever read from the client. Don't print secrets: anything printed is visible here. */
#pragma once

#include <stdint.h>

#define NETLOG_PORT 2323

/* Hooks the console output. Call first thing in main(), before anything worth logging. Also prints the
 * reset reason of this boot. */
void netlog_init(void);

/* Starts the TCP server task. Any time after netlog_init(); it waits for lwIP itself. */
void netlog_start(uint16_t port);

/* Prints free and minimum-ever FreeRTOS heap and each task's unused stack (also every 10 min from the
 * server task). Not reentrant: call from one task at a time. */
void netlog_print_memory(void);
