#include "harness.h"
#include "tm_dp.h"
#include "tm_frame.h"
#include "tm_time.h"
#include "tm_allow.h"
#include "tests.h"

static void test_checksum(void)
{
    const uint8_t a[] = {0x55, 0xAA, 0x00, 0x00, 0x00, 0x00};
    CHECK_EQ(tm_checksum(a, sizeof a), 0xFF);
    const uint8_t b[] = {0xFF, 0x02};
    CHECK_EQ(tm_checksum(b, 2), 0x01); /* wraps */
    CHECK_EQ(tm_checksum(a, 0), 0);
    uint8_t out[16];
    CHECK_EQ(tm_frame_build(out, sizeof out, 0, 0, NULL, 0), 7);
    const uint8_t hb[] = {0x55, 0xAA, 0x00, 0x00, 0x00, 0x00, 0xFF};
    CHECK_MEM(out, hb, 7); /* the well-known heartbeat query */
    CHECK_EQ(tm_frame_build(out, 6, 0, 0, NULL, 0), 0);
}

typedef struct { tm_parser p; uint8_t buf[300]; int frames; uint8_t cmd, ver; uint16_t len; uint8_t d0; } pctx;

static void pfeed(pctx *c, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        for (bool got = tm_parser_feed(&c->p, b[i]); got; got = tm_parser_next(&c->p)) {
            c->frames++;
            c->cmd = c->p.frame.cmd;
            c->ver = c->p.frame.ver;
            c->len = c->p.frame.len;
            c->d0 = c->p.frame.len ? c->p.frame.data[0] : 0;
        }
}

static void pinit(pctx *c, size_t cap)
{
    *c = (pctx){0};
    tm_parser_init(&c->p, c->buf, cap);
}

static void test_parser_basic_and_resync(void)
{
    pctx c;
    uint8_t f1[32], f2[32];
    const uint8_t d[] = {0x42, 0x55, 0xAA}; /* payload containing a header pattern */
    size_t n1 = tm_frame_build(f1, sizeof f1, 3, 0x07, d, sizeof d);
    size_t n2 = tm_frame_build(f2, sizeof f2, 3, 0x08, NULL, 0);

    pinit(&c, 256);
    pfeed(&c, f1, n1);
    CHECK_EQ(c.frames, 1);
    CHECK_EQ(c.cmd, 7);
    CHECK_EQ(c.ver, 3);
    CHECK_EQ(c.len, 3);
    CHECK_EQ(c.d0, 0x42);

    /* garbage (including lone 55s and 55 55 AA) then a frame */
    const uint8_t junk[] = {0x00, 0x55, 0x12, 0x55, 0x55, 0xFF, 0xAA, 0xAA, 0x55};
    pinit(&c, 256);
    pfeed(&c, junk, sizeof junk);
    pfeed(&c, f1, n1);
    CHECK_EQ(c.frames, 1);
    const uint8_t dbl[] = {0x55, 0x55, 0xAA}; /* 55 | 55 AA starts a header */
    pinit(&c, 256);
    pfeed(&c, dbl, 3);
    pfeed(&c, f2 + 2, n2 - 2);
    CHECK_EQ(c.frames, 1);
    CHECK_EQ(c.cmd, 8);

    /* bad checksum is dropped and counted, next frame still parses */
    uint8_t bad[32];
    memcpy(bad, f1, n1);
    bad[n1 - 1] ^= 0x01;
    pinit(&c, 256);
    pfeed(&c, bad, n1);
    CHECK_EQ(c.frames, 0);
    CHECK_EQ(c.p.bad_sum, 1);
    pfeed(&c, f2, n2);
    CHECK_EQ(c.frames, 1);

    /* oversized length is dropped and counted, then resync */
    pinit(&c, 9); /* max payload 2 */
    pfeed(&c, f1, n1);
    CHECK_EQ(c.frames, 0);
    CHECK_EQ(c.p.overflow, 1);
    pfeed(&c, f2, n2);
    CHECK_EQ(c.frames, 1);

    /* a fake header whose length swallows the start of a real frame: the real one is still found */
    const uint8_t fake_hdr[] = {0x55, 0xAA, 0xFF};
    pinit(&c, 256);
    pfeed(&c, fake_hdr, sizeof fake_hdr);
    pfeed(&c, f1, n1);
    CHECK_EQ(c.frames, 1);
    CHECK_EQ(c.cmd, 7);
    const uint8_t fake_hdr2[] = {0x55, 0xAA, 0x03, 0x07, 0x00, 0x02, 0x11}; /* short fake, bad sum */
    pinit(&c, 256);
    pfeed(&c, fake_hdr2, sizeof fake_hdr2);
    pfeed(&c, f2, n2);
    pfeed(&c, f2, n2);
    CHECK_EQ(c.frames, 2); /* the rescan recovers the first f2 from the fake frame's tail */
    CHECK_EQ(c.cmd, 8);

    /* a corrupted length swallows two frames: the re-scan finds both, not just the first */
    uint8_t three[64];
    memcpy(three, f1, n1);
    three[5] = 0x14; /* length 3 -> 20: swallows f2 and f1 up to its checksum byte */
    memcpy(three + n1, f2, n2);
    memcpy(three + n1 + n2, f1, n1);
    size_t n3 = n1 + n2 + n1;
    pinit(&c, 256);
    pfeed(&c, three, n3);
    CHECK_EQ(c.p.bad_sum, 1);
    CHECK_EQ(c.frames, 2);
    CHECK_EQ(c.cmd, 7); /* the trailing f1 */
    CHECK_EQ(c.d0, 0x42);
    pfeed(&c, f2, n2); /* and the parser is in sync afterwards */
    CHECK_EQ(c.frames, 3);
    three[5] = 0x0E; /* length 3 -> 14: ends inside the trailing f1, whose rest is queued */
    pinit(&c, 256);
    pfeed(&c, three, n3);
    CHECK_EQ(c.frames, 2);
    CHECK_EQ(c.cmd, 7);
    three[5] = 0x14;
    /* a caller that skips tm_parser_next() gets the queued frames with its next bytes */
    tm_parser p;
    uint8_t pbuf[64];
    int got = 0;
    tm_parser_init(&p, pbuf, sizeof pbuf);
    for (size_t i = 0; i < n3; i++) got += tm_parser_feed(&p, three[i]);
    CHECK_EQ(got, 1);
    for (size_t i = 0; i < n2; i++) got += tm_parser_feed(&p, f2[i]);
    CHECK_EQ(got, 3);

    /* back-to-back frames */
    uint8_t both[64];
    memcpy(both, f1, n1);
    memcpy(both + n1, f2, n2);
    pinit(&c, 256);
    pfeed(&c, both, n1 + n2);
    CHECK_EQ(c.frames, 2);
}

static void test_parser_split(void)
{
    pctx c;
    uint8_t f[300], payload[260];
    for (int i = 0; i < 260; i++) payload[i] = (uint8_t)i;
    size_t n = tm_frame_build(f, sizeof f, 0, 0x07, payload, sizeof payload);
    CHECK_EQ(n, 267);
    for (size_t cut = 1; cut < n; cut += 13) { /* split at various points */
        pinit(&c, 300);
        pfeed(&c, f, cut);
        CHECK_EQ(c.frames, 0);
        pfeed(&c, f + cut, n - cut);
        CHECK_EQ(c.frames, 1);
        CHECK_EQ(c.len, 260);
    }
    pinit(&c, 300); /* byte by byte */
    for (size_t i = 0; i < n; i++) pfeed(&c, f + i, 1);
    CHECK_EQ(c.frames, 1);
}

typedef struct { int n; tm_dp dp[8]; uint32_t u[8]; uint8_t first[8]; } dctx;

static void dcb(void *ctx, const tm_dp *dp)
{
    dctx *d = ctx;
    d->dp[d->n] = *dp;
    d->u[d->n] = tm_dp_u32(dp);
    d->first[d->n] = dp->len ? dp->data[0] : 0;
    d->n++;
}

static void test_dp_codec(void)
{
    uint8_t b[128];
    size_t n = 0;
    n += tm_dp_put_bool(b + n, sizeof b - n, 1, true);
    n += tm_dp_put_value(b + n, sizeof b - n, 16, 215);
    n += tm_dp_put_enum(b + n, sizeof b - n, 2, 1);
    n += tm_dp_put_bitmap(b + n, sizeof b - n, 104, 2);
    n += tm_dp_put(b + n, sizeof b - n, 119, TM_DP_RAW, (const uint8_t *)"\x01\x02\x03", 3);
    n += tm_dp_put(b + n, sizeof b - n, 50, TM_DP_STRING, (const uint8_t *)"hi", 2);
    CHECK_EQ(n, 5 + 8 + 5 + 8 + 7 + 6);
    const uint8_t exp_bool[] = {1, 1, 0, 1, 1};
    CHECK_MEM(b, exp_bool, 5);
    const uint8_t exp_val[] = {16, 2, 0, 4, 0, 0, 0, 215};
    CHECK_MEM(b + 5, exp_val, 8);

    dctx d = {0};
    CHECK_EQ(tm_dp_decode(b, n, dcb, &d), 6);
    CHECK_EQ(d.dp[0].type, TM_DP_BOOL);
    CHECK_EQ(d.u[0], 1);
    CHECK_EQ(d.dp[1].id, 16);
    CHECK_EQ(d.dp[1].type, TM_DP_VALUE);
    CHECK_EQ(d.u[1], 215);
    CHECK_EQ(d.dp[2].type, TM_DP_ENUM);
    CHECK_EQ(d.u[2], 1);
    CHECK_EQ(d.dp[3].type, TM_DP_BITMAP);
    CHECK_EQ(d.u[3], 2);
    CHECK_EQ(d.dp[4].type, TM_DP_RAW);
    CHECK_EQ(d.dp[4].len, 3);
    CHECK_EQ(d.first[4], 1);
    CHECK_EQ(d.dp[5].type, TM_DP_STRING);
    CHECK_EQ(d.dp[5].len, 2);

    /* negative values round-trip */
    uint8_t nb[8];
    CHECK_EQ(tm_dp_put_value(nb, sizeof nb, 112, -5), 8);
    const uint8_t *cur = nb;
    tm_dp dp;
    CHECK_EQ(tm_dp_next(&cur, nb + 8, &dp), 1);
    CHECK_EQ(tm_dp_i32(&dp), -5);
    CHECK_EQ(tm_dp_next(&cur, nb + 8, &dp), 0);

    /* truncated record: earlier ones delivered, -1 returned */
    d = (dctx){0};
    CHECK_EQ(tm_dp_decode(b, 5 + 6, dcb, &d), -1);
    CHECK_EQ(d.n, 1);

    /* illegal length for type is skipped but framing continues */
    const uint8_t odd[] = {1, TM_DP_BOOL, 0, 2, 1, 1, 2, TM_DP_ENUM, 0, 1, 7};
    d = (dctx){0};
    CHECK_EQ(tm_dp_decode(odd, sizeof odd, dcb, &d), 1);
    CHECK_EQ(d.dp[0].id, 2);

    /* encoder limits */
    uint8_t small[4];
    CHECK_EQ(tm_dp_put_bool(small, sizeof small, 1, true), 0);
    CHECK_EQ(tm_dp_put(small, sizeof small, 1, TM_DP_VALUE, (const uint8_t *)"ab", 2), 0);
    CHECK_EQ(tm_dp_put(small, sizeof small, 1, 9, NULL, 0), 0);
    CHECK(tm_dp_len_ok(TM_DP_BITMAP, 2) && !tm_dp_len_ok(TM_DP_BITMAP, 3));
}

static void test_time_and_allow(void)
{
    uint8_t o[8];
    tm_time t = {2026, 10, 17, 14, 5, 9, 6};
    const uint8_t loc[] = {1, 26, 10, 17, 14, 5, 9, 6};
    CHECK_EQ(tm_time_encode(o, true, &t), 8);
    CHECK_MEM(o, loc, 8);
    CHECK_EQ(tm_time_encode(o, false, &t), 7);
    CHECK_MEM(o, loc, 7);
    const uint8_t none[] = {0, 0, 0, 0, 0, 0, 0, 0};
    CHECK_EQ(tm_time_encode(o, true, NULL), 8);
    CHECK_MEM(o, none, 8);

    const uint8_t ok[] = {1, 2, 16, 108, 109, 110, 111, 112, 113, 114};
    for (int id = 0; id < 256; id++) {
        bool in = memchr(ok, id, sizeof ok) != NULL;
        CHECK(tm_dp_write_allowed((uint8_t)id) == in);
    }
    CHECK(!tm_dp_write_allowed(115)); /* factory reset */
}

void run_codec_tests(void)
{
    RUN(test_checksum);
    RUN(test_parser_basic_and_resync);
    RUN(test_parser_split);
    RUN(test_dp_codec);
    RUN(test_time_and_allow);
}
