#include "mdns_sub.h"

#include <stdio.h>
#include <string.h>

#define NAME_MAX_LEN 255
#define LEGACY_TTL_S 10         /* RFC 6762 section 6.7 */
#define T_PTR 12
#define T_ANY 255
#define C_IN 1

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t be32(const uint8_t *p) { return (uint32_t)be16(p) << 16 | be16(p + 2); }
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)(v >> 16)); put16(p + 2, (uint16_t)v); }

static const char *svc_of(const mtp_msub_ent *e) { return e->operational ? "_matter._tcp" : "_matterc._udp"; }

static bool sub_name(char *o, size_t cap, const mtp_msub_ent *e)
{
    return (size_t)snprintf(o, cap, "%s._sub.%s.local", e->sub, svc_of(e)) < cap;
}

static bool inst_name(char *o, size_t cap, const mtp_msub_ent *e)
{
    return (size_t)snprintf(o, cap, "%s.%s.local", e->instance, svc_of(e)) < cap;
}

static bool eq_ci(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return false;
    }
    return !*a && !*b;
}

/* Wire name at `off` (compression followed) -> dotted text without a trailing dot; *next = offset after the name
 * as it sits at `off`. false on a malformed or oversized name, a loop, or a label holding a dot. */
static bool read_name(const uint8_t *p, size_t n, size_t off, char *dst, size_t cap, size_t *next)
{
    size_t w = 0;
    unsigned jumps = 0;
    bool jumped = false;
    for (;;) {
        uint8_t l;
        if (off >= n) return false;
        l = p[off];
        if ((l & 0xC0) == 0xC0) {
            size_t to;
            if (off + 1 >= n || ++jumps > 8) return false;
            to = (size_t)((l & 0x3F) << 8 | p[off + 1]);
            if (!jumped) *next = off + 2;
            jumped = true;
            off = to;
            continue;
        }
        if (l & 0xC0) return false;
        off++;
        if (!l) break;
        if (off + l > n || w + l + 2 > cap || w + l > NAME_MAX_LEN) return false;
        if (w) dst[w++] = '.';
        for (unsigned i = 0; i < l; i++) {
            if (p[off + i] == '.') return false;
            dst[w++] = (char)p[off + i];
        }
        off += l;
    }
    dst[w] = 0;
    if (!jumped) *next = off;
    return true;
}

/* Dotted text -> wire name at out[off]; returns the new offset, 0 if it doesn't fit or a label is bad. */
static size_t write_name(uint8_t *out, size_t cap, size_t off, const char *name)
{
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t l = dot ? (size_t)(dot - name) : strlen(name);
        if (!l || l > 63 || off + 1 + l + 1 > cap) return 0;
        out[off++] = (uint8_t)l;
        memcpy(out + off, name, l);
        off += l;
        name += l + (dot ? 1 : 0);
    }
    if (off + 1 > cap) return 0;
    out[off++] = 0;
    return off;
}

/* One PTR answer for entry e at out[off]; returns the new offset, 0 if it doesn't fit. */
static size_t write_ptr(uint8_t *out, size_t cap, size_t off, const mtp_msub_ent *e, uint32_t ttl)
{
    char nm[128];
    size_t len_at, end;
    bool named = e->sub ? sub_name(nm, sizeof nm, e) : (size_t)snprintf(nm, sizeof nm, "%s.local", svc_of(e)) < sizeof nm;
    if (!named || !(off = write_name(out, cap, off, nm))) return 0;
    if (off + 10 > cap) return 0;
    put16(out + off, T_PTR);
    put16(out + off + 2, C_IN);       /* shared record: no cache-flush bit */
    put32(out + off + 4, ttl);
    len_at = off + 8;
    if (!inst_name(nm, sizeof nm, e) || !(end = write_name(out, cap, off + 10, nm))) return 0;
    put16(out + len_at, (uint16_t)(end - (off + 10)));
    return end;
}

static void header(uint8_t *out, uint16_t id, uint16_t qd, uint16_t an)
{
    memset(out, 0, 12);
    put16(out, id);
    put16(out + 2, 0x8400);           /* response, authoritative */
    put16(out + 4, qd);
    put16(out + 6, an);
}

size_t mtp_msub_reply(const uint8_t *in, size_t n, bool legacy, const mtp_msub_ent *tab, unsigned cnt,
                      uint8_t *out, size_t cap, bool *unicast)
{
    uint32_t hit = 0;
    bool qu = false;
    char name[NAME_MAX_LEN + 2], full[128];
    size_t off = 12, q0 = 12, q1 = 12, w;
    unsigned qd, an, answers = 0;
    uint32_t ttl = legacy ? LEGACY_TTL_S : MTP_MSUB_TTL_S;

    *unicast = false;
    if (n < 12 || cnt > MTP_MSUB_MAX) return 0;
    if (in[2] & 0x80) return 0;                         /* a response */
    if (in[2] & 0x78) return 0;                         /* opcode != QUERY */
    qd = be16(in + 4);
    an = be16(in + 6);
    if (!qd || (legacy && qd != 1)) return 0;

    for (unsigned q = 0; q < qd; q++) {
        uint16_t type, cls;
        if (!read_name(in, n, off, name, sizeof name, &off) || off + 4 > n) return 0;
        type = be16(in + off);
        cls = be16(in + off + 2);
        off += 4;
        if (q == 0) { q0 = 12; q1 = off; }
        if ((type != T_PTR && type != T_ANY) || ((cls & 0x7FFF) != C_IN && (cls & 0x7FFF) != 255)) continue;
        for (unsigned i = 0; i < cnt; i++)
            if (sub_name(full, sizeof full, &tab[i]) && eq_ci(name, full)) {
                hit |= 1u << i;
                if (cls & 0x8000) qu = true;
            }
    }
    if (!hit) return 0;

    /* Known answers (the packet's answer section): drop what the querier already holds with >= half the TTL. */
    for (unsigned a = 0; a < an; a++) {
        char rdata[NAME_MAX_LEN + 2];
        uint16_t type, rdlen;
        uint32_t ttl_in;
        size_t rd_end;
        if (!read_name(in, n, off, name, sizeof name, &off) || off + 10 > n) break;
        type = be16(in + off);
        ttl_in = be32(in + off + 4);
        rdlen = be16(in + off + 8);
        off += 10;
        if (off + rdlen > n) break;
        rd_end = off + rdlen;
        if (type == T_PTR && read_name(in, n, off, rdata, sizeof rdata, &off))
            for (unsigned i = 0; i < cnt; i++)
                if ((hit >> i & 1) && ttl_in >= MTP_MSUB_TTL_S / 2 && sub_name(full, sizeof full, &tab[i]) &&
                    eq_ci(name, full) && inst_name(full, sizeof full, &tab[i]) && eq_ci(rdata, full))
                    hit &= ~(1u << i);
        off = rd_end;
    }
    if (!hit) return 0;

    if (cap < 12) return 0;
    w = 12;
    if (legacy) {
        if (cap < w + (q1 - q0)) return 0;
        memcpy(out + w, in + q0, q1 - q0);
        w += q1 - q0;
    }
    for (unsigned i = 0; i < cnt; i++) {
        size_t nw;
        if (!(hit >> i & 1)) continue;
        if (!(nw = write_ptr(out, cap, w, &tab[i], ttl))) break;
        w = nw;
        answers++;
    }
    if (!answers) return 0;
    header(out, legacy ? be16(in) : 0, legacy ? 1 : 0, (uint16_t)answers);
    *unicast = legacy || qu;
    return w;
}

static size_t ptr_set(const mtp_msub_ent *tab, unsigned cnt, uint8_t *out, size_t cap, uint32_t ttl)
{
    size_t w = 12;
    unsigned answers = 0;
    if (cap < 12) return 0;
    for (unsigned i = 0; i < cnt; i++) {
        size_t nw = write_ptr(out, cap, w, &tab[i], ttl);
        if (!nw) break;
        w = nw;
        answers++;
    }
    if (!answers) return 0;
    header(out, 0, 0, (uint16_t)answers);
    return w;
}

size_t mtp_msub_announce(const mtp_msub_ent *tab, unsigned cnt, uint8_t *out, size_t cap)
{
    return ptr_set(tab, cnt, out, cap, MTP_MSUB_TTL_S);
}

size_t mtp_msub_goodbye(const mtp_msub_ent *tab, unsigned cnt, uint8_t *out, size_t cap)
{
    return ptr_set(tab, cnt, out, cap, 0);
}
