#include "tm_frame.h"

enum { S_H1, S_H2, S_VER, S_CMD, S_LENH, S_LENL, S_DATA, S_SUM };

uint8_t tm_checksum(const uint8_t *p, size_t n)
{
    uint8_t s = 0;
    while (n--) s = (uint8_t)(s + *p++);
    return s;
}

size_t tm_frame_build(uint8_t *out, size_t cap, uint8_t ver, uint8_t cmd, const uint8_t *data,
                      size_t len)
{
    if (len > 0xFFFFu || cap < len + TM_FRAME_OVERHEAD) return 0;
    out[0] = 0x55;
    out[1] = 0xAA;
    out[2] = ver;
    out[3] = cmd;
    out[4] = (uint8_t)(len >> 8);
    out[5] = (uint8_t)len;
    for (size_t i = 0; i < len; i++) out[6 + i] = data[i];
    out[6 + len] = tm_checksum(out, 6 + len);
    return len + TM_FRAME_OVERHEAD;
}

void tm_parser_init(tm_parser *p, uint8_t *buf, size_t bufsize)
{
    p->buf = buf;
    p->cap = bufsize > TM_FRAME_OVERHEAD ? bufsize - TM_FRAME_OVERHEAD : 0;
    if (p->cap > 0xFFFFu) p->cap = 0xFFFFu;
    p->pos = 0;
    p->want = 0;
    p->state = S_H1;
    p->sum = 0;
    p->frame = (tm_frame){0, 0, buf + 6, 0};
    p->bad_sum = 0;
    p->overflow = 0;
    p->queued_at = 0;
    p->queued = 0;
}

/* One state-machine step; every byte of a candidate frame is kept in buf for rescanning.
 * Returns 1 = frame complete, -1 = candidate dropped, 0 = need more. */
static int step(tm_parser *p, uint8_t b)
{
    switch (p->state) {
    case S_H1:
        if (b == 0x55) {
            p->buf[0] = b;
            p->pos = 1;
            p->state = S_H2;
        }
        return 0;
    case S_H2:
        if (b == 0xAA) {
            p->buf[p->pos++] = b;
            p->state = S_VER;
            p->sum = 0xFF; /* 0x55 + 0xAA */
        } else if (b != 0x55) {
            p->state = S_H1;
            p->pos = 0;
        }
        return 0;
    case S_LENL:
        p->want = (uint16_t)((p->buf[4] << 8) | b);
        break;
    default:
        break;
    }
    p->buf[p->pos++] = b;
    if (p->state != S_SUM) p->sum = (uint8_t)(p->sum + b);
    switch (p->state) {
    case S_VER: p->frame.ver = b; p->state = S_CMD; break;
    case S_CMD: p->frame.cmd = b; p->state = S_LENH; break;
    case S_LENH: p->state = S_LENL; break;
    case S_LENL:
        if (p->want > p->cap) {
            p->overflow++;
            p->state = S_H1;
            return -1;
        }
        p->state = p->want ? S_DATA : S_SUM;
        break;
    case S_DATA:
        if (p->pos == 6u + p->want) p->state = S_SUM;
        break;
    default: /* S_SUM */
        p->state = S_H1;
        if (b == p->sum) {
            p->frame.data = p->buf + 6;
            p->frame.len = p->want;
            p->pos = 0;
            return 1;
        }
        p->bad_sum++;
        return -1;
    }
    return 0;
}

/* Steps through bytes already taken from the UART, buf[i..n), from a fresh state. A dropped candidate
 * is replayed after the first byte that could start a header. A completed frame is returned and the
 * bytes after it stay queued for tm_parser_next(); the frame lies before them, so it stays intact. */
static bool replay(tm_parser *p, size_t i, size_t n)
{
    for (;;) {
        p->state = S_H1;
        p->pos = 0;
        int r = 0;
        for (; i < n; i++) /* writes land at index < i, so in-place replay is safe */
            if ((r = step(p, p->buf[i])) != 0) break;
        if (r == 0) return false;
        size_t rest = n - i - 1;
        if (r > 0) {
            p->queued_at = i + 1;
            p->queued = rest;
            return true;
        }
        /* failed again: keep what is left unreplayed after the kept bytes */
        for (size_t j = 0; j < rest; j++) p->buf[p->pos + j] = p->buf[i + 1 + j];
        n = p->pos + rest;
        for (i = 1; i < n && p->buf[i] != 0x55; i++) {}
    }
}

/* Moves the queued bytes to the front of buf (the last frame is no longer needed); returns their count. */
static size_t unqueue(tm_parser *p)
{
    size_t n = p->queued;
    for (size_t j = 0; j < n; j++) p->buf[j] = p->buf[p->queued_at + j];
    p->queued = 0;
    return n;
}

bool tm_parser_feed(tm_parser *p, uint8_t b)
{
    if (p->queued) { /* the caller skipped tm_parser_next(): the queued bytes come before b */
        size_t n = unqueue(p);
        p->buf[n] = b; /* fits: the queued bytes followed a frame of >= 7 bytes in buf */
        return replay(p, 0, n + 1);
    }
    int r = step(p, b);
    if (r > 0) return true;
    if (r == 0) return false;
    size_t i = 1;
    while (i < p->pos && p->buf[i] != 0x55) i++;
    return replay(p, i, p->pos);
}

bool tm_parser_next(tm_parser *p)
{
    if (!p->queued) return false;
    size_t n = unqueue(p);
    return replay(p, 0, n);
}
