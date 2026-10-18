/* mdns_sub: subtype PTR answers (RFC 6763 section 7.1, RFC 6762 sections 6.7 / 7.1, Matter spec 4.3.1). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mdns_sub.h"

static int *F;
#define CHECK(c) do { if (!(c)) { (*F)++; fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); } } while (0)

static const mtp_msub_ent TAB[] = {
    { "_L3840", "0123456789ABCDEF", false },
    { "_S15", "0123456789ABCDEF", false },
    { "_CM", "0123456789ABCDEF", false },
    { "_I1122334455667788", "1122334455667788-00000000000000AB", true },
};
#define NT (sizeof TAB / sizeof TAB[0])

/* Wire name of a dotted string at b[o]; returns new offset. */
static size_t nm(uint8_t *b, size_t o, const char *s)
{
    while (*s) {
        const char *d = strchr(s, '.');
        size_t l = d ? (size_t)(d - s) : strlen(s);
        b[o++] = (uint8_t)l;
        memcpy(b + o, s, l);
        o += l;
        s += l + (d ? 1 : 0);
    }
    b[o++] = 0;
    return o;
}

static size_t query(uint8_t *b, const char *name, unsigned type, unsigned cls)
{
    size_t o;
    memset(b, 0, 12);
    b[5] = 1;
    o = nm(b, 12, name);
    b[o++] = (uint8_t)(type >> 8); b[o++] = (uint8_t)type;
    b[o++] = (uint8_t)(cls >> 8); b[o++] = (uint8_t)cls;
    return o;
}

static size_t add_known(uint8_t *b, size_t o, const char *name, const char *inst, unsigned ttl)
{
    size_t lenat;
    o = nm(b, o, name);
    b[o++] = 0; b[o++] = 12; b[o++] = 0; b[o++] = 1;
    b[o++] = (uint8_t)(ttl >> 24); b[o++] = (uint8_t)(ttl >> 16); b[o++] = (uint8_t)(ttl >> 8); b[o++] = (uint8_t)ttl;
    lenat = o; o += 2;
    o = nm(b, o, inst);
    b[lenat] = 0; b[lenat + 1] = (uint8_t)(o - lenat - 2);
    b[7]++;
    return o;
}

static void test_basic(void)
{
    uint8_t q[512], r[512];
    bool uni;
    size_t n = query(q, "_S15._sub._matterc._udp.local", 12, 1), l;
    uint8_t want[512];
    size_t o;

    l = mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni);
    CHECK(l > 12 && !uni);
    CHECK(r[0] == 0 && r[1] == 0);                 /* multicast responses carry id 0 */
    CHECK(r[2] == 0x84 && r[3] == 0);              /* QR | AA */
    CHECK(r[4] == 0 && r[5] == 0 && r[6] == 0 && r[7] == 1 && r[8] == 0 && r[9] == 0 && r[10] == 0 && r[11] == 0);
    /* name, type PTR, class IN, ttl 120, rdata = instance FQDN */
    o = nm(want, 0, "_S15._sub._matterc._udp.local");
    CHECK(!memcmp(r + 12, want, o));
    CHECK(r[12 + o] == 0 && r[13 + o] == 12 && r[14 + o] == 0 && r[15 + o] == 1);
    CHECK(r[16 + o] == 0 && r[17 + o] == 0 && r[18 + o] == 0 && r[19 + o] == 120);
    {
        size_t rl = nm(want, 0, "0123456789ABCDEF._matterc._udp.local");
        CHECK(r[20 + o] == 0 && r[21 + o] == rl);
        CHECK(!memcmp(r + 22 + o, want, rl));
        CHECK(l == 22 + o + rl);
    }
    /* case-insensitive, ANY type, QU bit -> unicast */
    n = query(q, "_s15._SUB._MatterC._udp.LOCAL", 255, 0x8001);
    l = mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni);
    CHECK(l > 12 && uni);
    /* operational subtype on _matter._tcp */
    n = query(q, "_I1122334455667788._sub._matter._tcp.local", 12, 1);
    l = mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni);
    CHECK(l > 12 && !uni);
    o = nm(want, 0, "1122334455667788-00000000000000AB._matter._tcp.local");
    CHECK(!memcmp(r + l - o, want, o));
}

static void test_ignored(void)
{
    uint8_t q[512], r[512];
    bool uni;
    size_t n;
    n = query(q, "_S16._sub._matterc._udp.local", 12, 1);          /* other value */
    CHECK(mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni) == 0);
    n = query(q, "_S15._sub._matter._tcp.local", 12, 1);           /* wrong service */
    CHECK(mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni) == 0);
    n = query(q, "_matterc._udp.local", 12, 1);                    /* the plain type is lwIP's */
    CHECK(mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni) == 0);
    n = query(q, "_S15._sub._matterc._udp.local", 16, 1);          /* TXT */
    CHECK(mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni) == 0);
    n = query(q, "_S15._sub._matterc._udp.local", 12, 3);          /* class CH */
    CHECK(mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni) == 0);
    n = query(q, "_S15._sub._matterc._udp.local", 12, 1);
    q[2] |= 0x80;                                                   /* a response */
    CHECK(mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni) == 0);
    q[2] = 0x08;                                                    /* opcode 1 */
    CHECK(mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni) == 0);
    q[2] = 0;
    CHECK(mtp_msub_reply(q, n - 1, false, TAB, NT, r, sizeof r, &uni) == 0);   /* truncated */
    CHECK(mtp_msub_reply(q, 5, false, TAB, NT, r, sizeof r, &uni) == 0);
    CHECK(mtp_msub_reply(q, n, false, TAB, 0, r, sizeof r, &uni) == 0);
    CHECK(mtp_msub_reply(q, n, false, TAB, NT, r, 20, &uni) == 0);              /* no room */
    {   /* a compression loop in the question name must not hang or answer */
        uint8_t loop[32] = { 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 12, 0, 1 };
        CHECK(mtp_msub_reply(loop, 18, false, TAB, NT, r, sizeof r, &uni) == 0);
    }
}

static void test_known_answers(void)
{
    uint8_t q[512], r[512];
    bool uni;
    size_t n = query(q, "_S15._sub._matterc._udp.local", 12, 1);
    n = add_known(q, n, "_S15._sub._matterc._udp.local", "0123456789ABCDEF._matterc._udp.local", 100);
    CHECK(mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni) == 0);        /* >= half TTL: suppressed */
    n = query(q, "_S15._sub._matterc._udp.local", 12, 1);
    n = add_known(q, n, "_S15._sub._matterc._udp.local", "0123456789ABCDEF._matterc._udp.local", 30);
    CHECK(mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni) > 12);        /* stale: answer */
    n = query(q, "_S15._sub._matterc._udp.local", 12, 1);
    n = add_known(q, n, "_S15._sub._matterc._udp.local", "FEDCBA9876543210._matterc._udp.local", 120);
    CHECK(mtp_msub_reply(q, n, false, TAB, NT, r, sizeof r, &uni) > 12);        /* other instance: answer */
}

static void test_legacy(void)
{
    uint8_t q[512], r[512];
    bool uni;
    size_t n = query(q, "_L3840._sub._matterc._udp.local", 12, 1), l;
    q[0] = 0xAB; q[1] = 0xCD;
    l = mtp_msub_reply(q, n, true, TAB, NT, r, sizeof r, &uni);
    CHECK(l > n && uni);
    CHECK(r[0] == 0xAB && r[1] == 0xCD);           /* id echoed */
    CHECK(r[5] == 1 && r[7] == 1);                 /* question repeated */
    CHECK(!memcmp(r + 12, q + 12, n - 12));
    {   /* TTL <= 10 s: the answers start at n; its name is as long as the question's (n-16), then type, class */
        size_t ttl_at = n + (n - 4 - 12) + 4;
        CHECK(r[ttl_at] == 0 && r[ttl_at + 1] == 0 && r[ttl_at + 2] == 0 && r[ttl_at + 3] == 10);
    }
}

static void test_announce(void)
{
    uint8_t r[1024];
    size_t l = mtp_msub_announce(TAB, NT, r, sizeof r);
    CHECK(l > 12 && r[2] == 0x84 && r[7] == NT && r[0] == 0 && r[1] == 0);
    /* small buffer: fewer answers, count matches */
    l = mtp_msub_announce(TAB, NT, r, 120);
    CHECK(l > 12 && l <= 120 && r[7] >= 1 && r[7] < NT);
    CHECK(mtp_msub_announce(TAB, 0, r, sizeof r) == 0);
    CHECK(mtp_msub_announce(TAB, NT, r, 8) == 0);
}

static void test_goodbye(void)
{
    static const mtp_msub_ent gone[] = { { NULL, "0123456789ABCDEF", false }, { "_S15", "0123456789ABCDEF", false } };
    uint8_t r[512], w[128];
    size_t o, l = mtp_msub_goodbye(gone, 2, r, sizeof r);
    CHECK(l > 12 && r[2] == 0x84 && r[6] == 0 && r[7] == 2);
    /* first answer: _matterc._udp.local PTR, class IN without cache flush, TTL 0, rdata = the instance name */
    o = nm(w, 0, "_matterc._udp.local");
    CHECK(!memcmp(r + 12, w, o));
    CHECK(r[12 + o] == 0 && r[13 + o] == 12 && r[14 + o] == 0 && r[15 + o] == 1);
    CHECK(!r[16 + o] && !r[17 + o] && !r[18 + o] && !r[19 + o]);
    {
        size_t rl = (size_t)(r[20 + o] << 8 | r[21 + o]), il = nm(w, 0, "0123456789ABCDEF._matterc._udp.local");
        CHECK(rl == il && !memcmp(r + 22 + o, w, il));
        o = 22 + o + rl;
    }
    /* second answer: the subtype PTR, also TTL 0 */
    {
        size_t sl = nm(w, 0, "_S15._sub._matterc._udp.local");
        CHECK(!memcmp(r + o, w, sl));
        CHECK(!r[o + sl + 4] && !r[o + sl + 5] && !r[o + sl + 6] && !r[o + sl + 7]);
    }
    CHECK(mtp_msub_goodbye(gone, 0, r, sizeof r) == 0);
}

/* LAN input: mutated queries (bit flips, random bytes, compression pointers anywhere, truncation, junk tails) into
 * exactly sized heap buffers, so ASan sees any read past the packet and any write past `cap`. Deterministic. */
static uint32_t fz_state = 12345;
static uint32_t fz(void)
{
    fz_state ^= fz_state << 13;
    fz_state ^= fz_state >> 17;
    fz_state ^= fz_state << 5;
    return fz_state;
}

static void test_fuzz(void)
{
    static const char *names[] = { "_S15._sub._matterc._udp.local", "_I1122334455667788._sub._matter._tcp.local",
                                   "_cm._SUB._matterc._udp.local" };
    static uint8_t in[1024];
    unsigned replies = 0, bad = 0;
    for (long it = 0; it < 200000; it++) {
        size_t o = 12, n, cap;
        unsigned nq = 1 + fz() % 3;
        bool uni;
        memset(in, 0, 12);
        in[5] = (uint8_t)nq;
        for (unsigned q = 0; q < nq; q++) {
            if (q && fz() % 2) { in[o++] = 0xC0; in[o++] = 12; }
            else o = nm(in, o, names[fz() % 3]);
            in[o++] = 0; in[o++] = (fz() % 2) ? 12 : 255; in[o++] = (fz() % 2) ? 0x80 : 0; in[o++] = 1;
        }
        if (fz() % 2) o = add_known(in, o, names[0], "0123456789ABCDEF._matterc._udp.local", 120);
        n = o;
        for (unsigned m = fz() % 8; m; m--) {
            switch (fz() % 5) {
            case 0: in[fz() % n] = (uint8_t)fz(); break;
            case 1: in[fz() % n] ^= (uint8_t)(1u << (fz() % 8)); break;
            case 2: { size_t p = fz() % n; in[p] = (uint8_t)(0xC0 | (fz() % 4)); if (p + 1 < n) in[p + 1] = (uint8_t)fz(); break; }
            case 3: n = 1 + fz() % n; break;
            default: { size_t add = fz() % (sizeof in - n); for (size_t i = 0; i < add; i++) in[n + i] = (uint8_t)fz(); n += add; }
            }
        }
        cap = (fz() % 4 == 0) ? fz() % 512 : 512;
        uint8_t *h = malloc(n), *out = malloc(cap ? cap : 1);
        if (!h || !out) { free(h); free(out); bad++; break; }
        memcpy(h, in, n);
        size_t r = mtp_msub_reply(h, n, fz() % 4 == 0, TAB, NT, out, cap, &uni);
        if (r > cap || (r && r < 12)) bad++;
        replies += r != 0;
        free(h);
        free(out);
    }
    CHECK(bad == 0);
    CHECK(replies > 1000);   /* the mutations leave many valid queries: the answer path is exercised too */
}

void test_mdns_sub(int *fails)
{
    F = fails;
    test_basic();
    test_ignored();
    test_known_answers();
    test_legacy();
    test_announce();
    test_goodbye();
    test_fuzz();
}
