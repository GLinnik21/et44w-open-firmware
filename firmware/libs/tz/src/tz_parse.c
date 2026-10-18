#include "tz.h"

#include <string.h>

static bool IsDigit(char c) { return c >= '0' && c <= '9'; }
static bool IsAlpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

static bool Name(const char **p)
{
    const char *s = *p;
    if (*s == '<') {
        while (*s && *s != '>') s++;
        if (*s != '>') return false;
        *p = s + 1;
        return true;
    }
    int n = 0;
    while (IsAlpha(*s)) s++, n++;
    *p = s;
    return n >= 3;
}

static bool Number(const char **p, int32_t max, int32_t *out)
{
    const char *s = *p;
    if (!IsDigit(*s)) return false;
    int32_t v = 0;
    while (IsDigit(*s)) {
        v = v * 10 + (*s++ - '0');
        if (v > max) return false;
    }
    *out = v;
    *p = s;
    return true;
}

/* [+-]hh[:mm[:ss]] -> seconds. */
static bool Time(const char **p, int32_t *out)
{
    const char *s = *p;
    int32_t sign = 1;
    if (*s == '+' || *s == '-') sign = *s++ == '-' ? -1 : 1;
    int32_t h, m = 0, sec = 0;
    if (!Number(&s, 167, &h)) return false;
    if (*s == ':' && (s++, !Number(&s, 59, &m))) return false;
    if (*s == ':' && (s++, !Number(&s, 59, &sec))) return false;
    *out = sign * (h * 3600 + m * 60 + sec);
    *p = s;
    return true;
}

static bool Rule(const char **p, tz_rule *r)
{
    const char *s = *p;
    int32_t m, w, d;
    if (*s++ != 'M' || !Number(&s, 12, &m) || m < 1 || *s++ != '.' || !Number(&s, 5, &w) || w < 1 ||
        *s++ != '.' || !Number(&s, 6, &d))
        return false;
    r->month = (uint8_t)m;
    r->week = (uint8_t)w;
    r->wday = (uint8_t)d;
    r->time = 7200;
    if (*s == '/' && (s++, !Time(&s, &r->time))) return false;
    *p = s;
    return true;
}

bool tz_parse(const char *spec, tz_zone *z)
{
    tz_zone t;
    memset(&t, 0, sizeof t);
    const char *s = spec;
    int32_t off;
    if (!s || !Name(&s) || !Time(&s, &off)) goto fail;
    t.std_offset = -off;
    if (*s) {
        if (!Name(&s)) goto fail;
        t.has_dst = true;
        t.dst_offset = t.std_offset + 3600;
        if (*s && *s != ',') {
            if (!Time(&s, &off)) goto fail;
            t.dst_offset = -off;
        }
        if (*s++ != ',' || !Rule(&s, &t.start) || *s++ != ',' || !Rule(&s, &t.end) || *s) goto fail;
    }
    *z = t;
    return true;
fail:
    memset(z, 0, sizeof *z);
    return false;
}
