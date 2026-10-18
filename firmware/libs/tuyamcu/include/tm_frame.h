/* TuyaMCU frame codec: 55 AA ver cmd len_hi len_lo data... sum (sum = all preceding bytes mod 256). */
#ifndef TM_FRAME_H
#define TM_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TM_FRAME_OVERHEAD 7u /* 55 AA ver cmd len(2) sum */

uint8_t tm_checksum(const uint8_t *p, size_t n);

/* Writes a complete frame to out. Returns its size, or 0 if it does not fit or len > 0xFFFF. */
size_t tm_frame_build(uint8_t *out, size_t cap, uint8_t ver, uint8_t cmd, const uint8_t *data,
                      size_t len);

typedef struct {
    uint8_t ver;
    uint8_t cmd;
    const uint8_t *data; /* points into the parser's payload buffer */
    uint16_t len;
} tm_frame;

/* Byte-at-a-time parser. The caller provides a buffer holding one whole raw frame: its size is
 * the largest payload accepted + TM_FRAME_OVERHEAD. */
typedef struct {
    uint8_t *buf;
    size_t cap; /* max payload */
    size_t pos;
    uint16_t want;
    uint8_t state;
    uint8_t sum;
    tm_frame frame;
    uint32_t bad_sum;  /* frames dropped for a wrong checksum */
    uint32_t overflow; /* frames dropped because len > cap */
    size_t queued_at;  /* bytes left after a frame found while re-scanning, for tm_parser_next() */
    size_t queued;
} tm_parser;

void tm_parser_init(tm_parser *p, uint8_t *buf, size_t bufsize);

/* Feeds one byte. Returns true when a valid frame completed; it is in p->frame until the next call.
 * Garbage, bad checksums and oversized frames are dropped; the bytes after the false header are
 * re-scanned, so real frames hidden behind a fake 55 AA are still found. One re-scan can complete
 * several frames: after a true return, call tm_parser_next() until it returns false. */
bool tm_parser_feed(tm_parser *p, uint8_t b);
/* The next frame from bytes already fed, if any (true = in p->frame, as for tm_parser_feed). */
bool tm_parser_next(tm_parser *p);

#endif
