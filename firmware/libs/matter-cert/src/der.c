#include <string.h>
#include "der.h"

#define RESERVED_LEN 3 /* length bytes held back by der_open: enough for content < 64 KiB */

static bool room(der_w *w, size_t n)
{
    if (w->err || n > w->cap - w->len) { w->err = true; return false; }
    return true;
}

static size_t put_len(uint8_t *p, size_t n)
{
    if (n < 0x80) { p[0] = (uint8_t)n; return 1; }
    if (n < 0x100) { p[0] = 0x81; p[1] = (uint8_t)n; return 2; }
    p[0] = 0x82; p[1] = (uint8_t)(n >> 8); p[2] = (uint8_t)n;
    return 3;
}

size_t der_open(der_w *w, uint8_t tag)
{
    size_t m = w->len;
    if (room(w, 1 + RESERVED_LEN)) {
        w->p[m] = tag;
        w->len += 1 + RESERVED_LEN;
    }
    return m;
}

void der_close(der_w *w, size_t m)
{
    if (w->err) return;
    size_t body = m + 1 + RESERVED_LEN, n = w->len - body;
    uint8_t hdr[RESERVED_LEN];
    size_t h = put_len(hdr, n);
    memmove(w->p + m + 1 + h, w->p + body, n);
    memcpy(w->p + m + 1, hdr, h);
    w->len = m + 1 + h + n;
}

void der_put(der_w *w, uint8_t tag, const void *v, size_t n)
{
    uint8_t hdr[1 + RESERVED_LEN];
    hdr[0] = tag;
    size_t h = 1 + put_len(hdr + 1, n);
    if (!room(w, h + n)) return;
    memcpy(w->p + w->len, hdr, h);
    if (n) memcpy(w->p + w->len + h, v, n);
    w->len += h + n;
}

void der_raw(der_w *w, const void *v, size_t n)
{
    if (!room(w, n)) return;
    memcpy(w->p + w->len, v, n);
    w->len += n;
}
