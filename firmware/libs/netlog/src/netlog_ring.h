/* Byte ring buffer shared by the console hook (writer, any context incl. ISRs) and the server task
 * (reader). Positions are running byte counts; a reader that falls more than NETLOG_RING_SIZE behind
 * loses the oldest bytes. */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define NETLOG_RING_SIZE 8192u /* power of two */

void netlog_ring_put(char c);

/* Running count of bytes ever written. */
uint32_t netlog_ring_head(void);

/* Copies up to n bytes starting at running position *pos into buf and advances *pos. If *pos was
 * overwritten already, it first jumps to the oldest kept byte and adds the skipped count to *lost. */
size_t netlog_ring_read(uint32_t* pos, char* buf, size_t n, uint32_t* lost);
