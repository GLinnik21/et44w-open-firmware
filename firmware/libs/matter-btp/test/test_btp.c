/* BTP engine tests. Handshake bytes follow connectedhomeip src/ble (BleLayer.cpp capabilities
 * request/response: 0x65 0x6C, version nibbles low-first, ATT MTU / segment size LE16, window) and the
 * header layouts in src/ble/BtpEngine.cpp / tests/TestBtpEngine.cpp (flags, [ack], seq, [len16]). */
#include <stdio.h>
#include <string.h>

#include "mt_btp.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_BYTES(got, n, ...) do { const uint8_t e_[] = { __VA_ARGS__ }; \
    CHECK((n) == sizeof e_ && memcmp(got, e_, sizeof e_) == 0); } while (0)

static uint8_t rxmem[1280], pk[256];
static mt_btp B;

static mt_err wr(uint32_t now, const uint8_t *p, size_t n) { return mt_btp_rx(&B, now, mt_span_of(p, n)); }
#define WR(now, ...) ({ const uint8_t p_[] = { __VA_ARGS__ }; wr(now, p_, sizeof p_); })
static size_t poll(uint32_t now) { return mt_btp_poll(&B, now, mt_buf_of(pk, sizeof pk)); }

/* Numbering (chip BtpEngine with the peripheral's expect_first_ack, matter.js BtpSessionHandler, iOS 27): the
 * central's handshake request carries no sequence number; our handshake response is our seq 0 and is outstanding
 * until the central acks it; our first data/ack packet is seq 1; the central's first packet is its seq 0. */
static void hs(uint16_t mtu, uint8_t win)
{
    uint8_t req[9] = { 0x65, 0x6C, 0x04, 0, 0, 0, 0, 0, win };
    mt_put_le16(req + 6, mtu);
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    CHECK(wr(0, req, 9) == MT_OK);
}

static void test_handshake(void)
{
    size_t n;
    hs(244, 6);
    n = poll(0);
    CHECK_BYTES(pk, n, 0x65, 0x6C, 0x04, 241, 0x00, 0x05); /* segment = MTU-3, window capped to ours */
    CHECK(poll(0) == 0);
    hs(23, 3);
    n = poll(0);
    CHECK_BYTES(pk, n, 0x65, 0x6C, 0x04, 20, 0x00, 0x03);
    hs(247, 5);
    n = poll(0);
    CHECK_BYTES(pk, n, 0x65, 0x6C, 0x04, 244, 0x00, 0x05); /* 247-3 = 244 = cap */
    hs(1000, 5);
    n = poll(0);
    CHECK(pk[3] == 244);

    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 100); /* MTU 0 = unknown: use the port's value */
    CHECK(WR(0, 0x65, 0x6C, 0x04, 0, 0, 0, 0, 0, 5) == MT_OK);
    n = poll(0);
    CHECK_BYTES(pk, n, 0x65, 0x6C, 0x04, 97, 0x00, 0x05);
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    CHECK(WR(0, 0x65, 0x6C, 0x04, 0, 0, 0, 0, 0, 5) == MT_OK);
    n = poll(0);
    CHECK(pk[3] == 20); /* default 23 */

    /* versions 4,3 listed (nibbles low first): accepted */
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    CHECK(WR(0, 0x65, 0x6C, 0x34, 0, 0, 0, 23, 0, 5) == MT_OK);
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    CHECK(WR(0, 0x65, 0x6C, 0x03, 0, 0, 0, 23, 0, 5) == MT_ERR_UNSUPPORTED && mt_btp_closed(&B));
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    CHECK(WR(0, 0x65, 0x6C, 0x04, 0, 0, 0, 23, 0, 0) == MT_ERR_INVALID); /* window 0 */
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    CHECK(WR(0, 0x05, 0x01, 0x01, 0x00, 0xAA) == MT_ERR_INVALID); /* data before handshake */
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    CHECK(WR(0, 0x65, 0x6C, 0x04, 0, 0, 0, 23, 0) == MT_ERR_INVALID); /* short */
}

static void test_ack_timer_and_single_message(void)
{
    size_t n;
    hs(244, 5);
    poll(0);
    /* the request is unnumbered: we owe no ack, only wait for the ack of our response (seq 0) */
    CHECK(mt_btp_wait_ms(&B, 0) == MT_BTP_ACK_WAIT_MS);
    CHECK(poll(2500) == 0);
    CHECK(mt_btp_wait_ms(&B, 2500) == MT_BTP_ACK_WAIT_MS - 2500);

    /* central's standalone ack of our response: ack 0, its seq 0 */
    CHECK(WR(3000, 0x08, 0x00, 0x00) == MT_OK);
    CHECK(mt_btp_wait_ms(&B, 3000) == MT_BTP_ACK_SEND_MS);
    CHECK(poll(3000 + MT_BTP_ACK_SEND_MS - 1) == 0);
    n = poll(3000 + MT_BTP_ACK_SEND_MS); /* our standalone ack of its seq 0, our seq 1 */
    CHECK_BYTES(pk, n, 0x08, 0x00, 0x01);
    CHECK(poll(5500) == 0);
    CHECK(mt_btp_wait_ms(&B, 5500) == MT_BTP_ACK_WAIT_MS);

    /* central acks our ack (seq 1) and sends a one-packet message, seq 1 */
    CHECK(WR(6000, 0x0D, 0x01, 0x01, 0x03, 0x00, 0xDE, 0xAD, 0xBF) == MT_OK);
    CHECK(mt_btp_msg(&B).len == 3 && mt_btp_msg(&B).p[2] == 0xBF);
    CHECK(mt_btp_wait_ms(&B, 6000) == MT_BTP_ACK_SEND_MS);
    /* a reply goes out with the ack piggybacked: ack 1, seq 2 */
    mt_btp_msg_release(&B);
    {
        const uint8_t m[] = { 1, 2, 3, 4 };
        CHECK(mt_btp_send(&B, mt_span_of(m, 4)) == MT_OK);
        CHECK(mt_btp_send(&B, mt_span_of(m, 4)) == MT_ERR_STATE); /* busy */
        n = poll(6001);
        CHECK_BYTES(pk, n, 0x0D, 0x01, 0x02, 0x04, 0x00, 1, 2, 3, 4);
        CHECK(mt_btp_tx_idle(&B));
        CHECK(poll(6001) == 0);
        CHECK(mt_btp_wait_ms(&B, 6001) == MT_BTP_ACK_WAIT_MS);
    }
    CHECK(WR(6100, 0x08, 0x02, 0x02) == MT_OK); /* peer's standalone ack of our seq 2, its seq 2 */
    /* it carries seq 2 and is acked in turn (chip BtpEngine::HasUnackedData; its sender runs the 15 s timer) */
    CHECK(mt_btp_wait_ms(&B, 6100) == MT_BTP_ACK_SEND_MS);
    CHECK(poll(6100 + MT_BTP_ACK_SEND_MS - 1) == 0);
    n = poll(6100 + MT_BTP_ACK_SEND_MS);
    CHECK_BYTES(pk, n, 0x08, 0x02, 0x03);
}

static void test_receive_segmented(size_t mtu, size_t len)
{
    uint8_t msg[1300], seq = 0, owe = 0; /* the central owes an ack of our response (seq 0) */
    size_t i, n, frag = mtu - 3 > 244 ? 244 : mtu - 3;
    int pk_n, acks = 0, owing = 1;
    for (i = 0; i < len; i++) msg[i] = (uint8_t)(i * 7 + 3);
    hs((uint16_t)mtu, 5);
    poll(0);
    /* send packet by packet, acking our packets on the next write like a real central would */
    {
        size_t off = 0;
        int first = 1;
        while (off < len) {
            uint8_t seg[256];
            mt_err r;
            size_t take;
            n = 0;
            seg[n++] = 0;
            if (owing) { seg[n++] = owe; owing = 0; }
            seg[n++] = seq++;
            if (first) { mt_put_le16(seg + n, (uint16_t)len); n += 2; }
            take = frag - n;
            if (len - off < take) take = len - off;
            seg[0] = (uint8_t)((first ? 1 : 2) | (off + take == len ? 4 : 0));
            if (!first && off + take == len) seg[0] = 4;
            if (n == 3 + (first ? 2 : 0)) seg[0] |= 0x08; /* ack field present */
            memcpy(seg + n, msg + off, take);
            r = wr(100, seg, n + take);
            CHECK(r == MT_OK);
            off += take;
            first = 0;
            while ((pk_n = (int)poll(100)) > 0) { /* immediate acks when our window runs low */
                CHECK(pk_n == 3 && (pk[0] & 0x0F) == 0x08);
                acks++;
                owe = pk[2];
                owing = 1;
            }
        }
    }
    CHECK(mt_btp_msg(&B).len == len && memcmp(mt_btp_msg(&B).p, msg, len) == 0);
    if (len > frag * 3)
        CHECK(acks >= 1);
    mt_btp_msg_release(&B);
}

static void test_receive(void)
{
    test_receive_segmented(23, 50);    /* S C E at 20-byte packets */
    test_receive_segmented(23, 16);    /* exactly one start packet payload */
    test_receive_segmented(23, 17);    /* one byte spills into End */
    test_receive_segmented(23, 400);
    test_receive_segmented(244, 1000);
    test_receive_segmented(247, 1280);
}

/* Reassemble what the engine emits, as a central would, acking per packet window. */
static size_t central_collect(uint32_t now, uint8_t *msg, size_t cap, uint8_t *cseq, int *npk, int ack_every)
{
    size_t got = 0, want = 0, n;
    int since = 0;
    *npk = 0;
    while ((n = poll(now)) > 0) {
        uint8_t fl = pk[0], *p = pk + 1;
        size_t hlen = 1;
        (*npk)++;
        if (fl & 8) { p++; hlen++; }
        hlen++; p++; /* seq */
        if (fl & 1) { want = mt_get_le16(p); p += 2; hlen += 2; }
        CHECK(got + n - hlen <= cap);
        memcpy(msg + got, p, n - hlen);
        got += n - hlen;
        if (++since == ack_every) {
            since = 0; /* central standalone ack: ack seq of last packet */
            CHECK(WR(now, 0x08, pk[(fl & 8) ? 2 : 1], (*cseq)++) == MT_OK);
        }
    }
    CHECK(got == want || want == 0);
    return got;
}

static void test_send_segmented(size_t mtu, size_t len, int expect_pkts)
{
    uint8_t msg[1300], got[1300], cseq = 0;
    size_t i, g, frag = mtu - 3 > 244 ? 244 : mtu - 3;
    int npk, total = 0;
    (void)frag;
    for (i = 0; i < len; i++) msg[i] = (uint8_t)(i ^ 0x5A);
    hs((uint16_t)mtu, 5);
    poll(0);
    CHECK(WR(0, 0x08, 0x00, cseq++) == MT_OK); /* central acks our response (0) with its seq 0 */
    CHECK(mt_btp_send(&B, mt_span_of(msg, len)) == MT_OK);
    g = 0;
    while (!mt_btp_tx_idle(&B)) {
        size_t c = central_collect(10, got + g, sizeof got - g, &cseq, &npk, 2);
        g += c;
        total += npk;
        CHECK(npk > 0);
        if (npk == 0) break;
    }
    CHECK(g == len && memcmp(got, msg, len) == 0);
    CHECK(total == expect_pkts);
    CHECK(!mt_btp_closed(&B));
}

static void test_send(void)
{
    /* MTU 23: first packet acks the central's seq 0 -> header 5, 15 bytes; then 18 per packet */
    test_send_segmented(23, 15, 1);
    test_send_segmented(23, 16, 2);
    test_send_segmented(23, 100, 1 + (100 - 15 + 17) / 18);
    test_send_segmented(244, 1000, 5);  /* 236 + 3*239... (241-2 each) */
    test_send_segmented(247, 1280, 6);
}

static void test_window_limit(void)
{
    uint8_t msg[400] = { 0 };
    int n = 0;
    hs(23, 5);
    poll(0);
    CHECK(mt_btp_send(&B, mt_span_of(msg, sizeof msg)) == MT_OK);
    while (poll(0) > 0) n++;
    CHECK(n == 3);                       /* the unacked response (seq 0) holds a slot */
    hs(23, 5);
    poll(0);
    CHECK(WR(0, 0x08, 0x00, 0x00) == MT_OK); /* central acks the response */
    CHECK(mt_btp_send(&B, mt_span_of(msg, sizeof msg)) == MT_OK);
    n = 0;
    while (poll(1) > 0) n++;
    CHECK(n == 4);                       /* window 5: last slot reserved for an ack */
    CHECK(!mt_btp_tx_idle(&B));
    CHECK(mt_btp_wait_ms(&B, 1) == MT_BTP_ACK_WAIT_MS - 0); /* nothing else to do until acked */
    CHECK(WR(2, 0x08, 0x03, 0x01) == MT_OK); /* acks seq 1..3 of ours (data seqs 1,2,3,4) */
    n = 0;
    while (poll(2) > 0) n++;
    CHECK(n == 3);                       /* outstanding {4}: three more fit */
}

static void test_window_one_and_two(void)
{
    uint8_t msg[40] = { 0 };
    hs(23, 1);
    poll(0);
    CHECK(mt_btp_send(&B, mt_span_of(msg, 10)) == MT_OK);
    CHECK(poll(0) == 0);                 /* the unacked response is the one outstanding packet */
    CHECK(WR(0, 0x08, 0x00, 0x00) == MT_OK);
    CHECK(poll(0) > 0 && poll(0) == 0); /* one outstanding at a time still works */
    hs(23, 2);
    poll(0);
    CHECK(mt_btp_send(&B, mt_span_of(msg, 10)) == MT_OK);
    CHECK(poll(0) == 0);
    CHECK(WR(0, 0x08, 0x00, 0x00) == MT_OK);
    CHECK(poll(0) > 0 && poll(0) == 0);
}

static void test_immediate_ack(void)
{
    hs(23, 5);
    poll(0);
    /* window 5 -> ack once 4 packets are pending (the request does not count: it is unnumbered) */
    CHECK(WR(1, 0x09, 0x00, 0x00, 0x30, 0x00, 1) == MT_OK); /* S, acks our response, seq 0, len 48 */
    CHECK(WR(1, 0x02, 0x01, 1) == MT_OK);
    CHECK(WR(1, 0x02, 0x02, 1) == MT_OK);
    CHECK(poll(1) == 0);
    CHECK(WR(1, 0x02, 0x03, 1) == MT_OK);
    {
        size_t n = poll(1);
        CHECK_BYTES(pk, n, 0x08, 0x03, 0x01);
    }
    CHECK(mt_btp_wait_ms(&B, 1) == UINT32_MAX || mt_btp_wait_ms(&B, 1) <= MT_BTP_ACK_WAIT_MS);
}

static void expect_close(mt_err want, int line, mt_err got)
{
    checks++;
    if (got != want || !mt_btp_closed(&B)) {
        fails++;
        printf("FAIL line %d: got %d want %d\n", line, got, want);
    }
    CHECK(mt_btp_error(&B) == want);
    CHECK(WR(0, 0x08, 0x00, 0x00) == MT_ERR_STATE); /* closed engines refuse everything */
    CHECK(poll(0) == 0);
}
#define X(want, expr) do { hs(23, 5); poll(0); expect_close(want, __LINE__, (expr)); } while (0)

static void test_errors(void)
{
    /* sequence numbers */
    X(MT_ERR_INVALID, WR(0, 0x05, 0x01, 0x01, 0x00, 1));          /* seq 1 first: the request has no number */
    X(MT_ERR_INVALID, WR(0, 0x05, 0x02, 0x01, 0x00, 1));          /* skipped seq */
    hs(23, 5); poll(0);
    CHECK(WR(0, 0x05, 0x00, 0x01, 0x00, 1) == MT_OK);
    mt_btp_msg_release(&B);
    expect_close(MT_ERR_INVALID, __LINE__, WR(0, 0x05, 0x00, 0x01, 0x00, 1)); /* replayed seq 0 */
    hs(23, 5); poll(0);
    CHECK(WR(0, 0x05, 0x00, 0x01, 0x00, 1) == MT_OK);
    mt_btp_msg_release(&B);
    expect_close(MT_ERR_INVALID, __LINE__, WR(0, 0x05, 0x02, 0x01, 0x00, 1)); /* skipped seq 1 */
    /* acks */
    hs(23, 5);                                                     /* response not yet sent */
    expect_close(MT_ERR_INVALID, __LINE__, WR(0, 0x0D, 0x00, 0x00, 0x01, 0x00, 1)); /* ack of an unsent 0 */
    hs(23, 5); poll(0);
    CHECK(WR(0, 0x08, 0x00, 0x00) == MT_OK);                       /* response acked: nothing outstanding */
    expect_close(MT_ERR_INVALID, __LINE__, WR(0, 0x0D, 0x00, 0x01, 0x01, 0x00, 1)); /* ack with nothing outstanding */
    X(MT_ERR_INVALID, WR(0, 0x08, 0x01, 0x00));                   /* ack of seq 1, only the response (0) sent */
    X(MT_ERR_INVALID, WR(0, 0x08, 0x05, 0x00));                   /* ack of seq 5, never sent */
    hs(23, 5); poll(0);
    CHECK(WR(0, 0x08, 0x00, 0x00) == MT_OK); poll(2500);          /* our standalone ack (seq 1) outstanding */
    expect_close(MT_ERR_INVALID, __LINE__, WR(0, 0x08, 0x00, 0x01)); /* re-ack of 0, already acked */
    /* flags and framing */
    X(MT_ERR_INVALID, WR(0, 0x11, 0x00, 0x01, 0x00, 1));          /* unknown flag bit */
    X(MT_ERR_INVALID, WR(0, 0x00, 0x00));                          /* no data, no ack */
    X(MT_ERR_INVALID, WR(0, 0x04, 0x00, 1));                       /* End without Start */
    X(MT_ERR_INVALID, WR(0, 0x02, 0x00, 1));                       /* Continue without Start */
    X(MT_ERR_INVALID, WR(0, 0x03, 0x00, 0x01, 0x00, 1));           /* Start+Continue */
    X(MT_ERR_INVALID, WR(0, 0x05, 0x00, 0x00, 0x00));              /* zero length */
    X(MT_ERR_INVALID, WR(0, 0x05, 0x00, 0x02, 0x00, 1));           /* End but 1 of 2 bytes */
    X(MT_ERR_INVALID, WR(0, 0x01, 0x00, 0x01, 0x00, 1));           /* all bytes in, no End */
    X(MT_ERR_INVALID, WR(0, 0x05, 0x00, 0x01, 0x00, 1, 2));        /* overflows declared length */
    X(MT_ERR_INVALID, WR(0, 0x05, 0x00, 0x01));                    /* Start without length */
    X(MT_ERR_STATE, WR(0, 0x65, 0x6C, 0x04, 0, 0, 0, 23, 0, 5));   /* second handshake */
    {
        uint8_t big[8] = { 0x05, 0x00, 0xFF, 0xFF, 0, 0, 0, 0 };
        hs(23, 5); poll(0);
        mt_btp_init(&B, mt_buf_of(rxmem, 100), 0);
        CHECK(WR(0, 0x65, 0x6C, 0x04, 0, 0, 0, 23, 0, 5) == MT_OK);
        expect_close(MT_ERR_BUFFER_TOO_SMALL, __LINE__, wr(0, big, 8));
    }
    /* mid-message errors */
    hs(23, 5); poll(0);
    CHECK(WR(0, 0x01, 0x00, 0x20, 0x00, 1) == MT_OK);
    expect_close(MT_ERR_INVALID, __LINE__, WR(0, 0x01, 0x01, 0x20, 0x00, 1)); /* new Start mid-message */
    /* next Start before the app released the previous message */
    hs(23, 5); poll(0);
    CHECK(WR(0, 0x05, 0x00, 0x01, 0x00, 1) == MT_OK);
    expect_close(MT_ERR_STATE, __LINE__, WR(0, 0x05, 0x01, 0x01, 0x00, 1));
    /* send before open / empty */
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    CHECK(mt_btp_send(&B, mt_span_of(rxmem, 4)) == MT_ERR_STATE);
    hs(23, 5);
    CHECK(mt_btp_send(&B, mt_span_of(rxmem, 0)) == MT_ERR_INVALID);
}

static void test_ack_timeout(void)
{
    uint8_t m[3] = { 1, 2, 3 };
    /* the handshake response waits for its ack like any packet */
    hs(23, 5);
    CHECK(poll(500) == 6);
    CHECK(mt_btp_wait_ms(&B, 500) == MT_BTP_ACK_WAIT_MS);
    CHECK(poll(500 + 14999) == 0 && mt_btp_open(&B));
    CHECK(poll(500 + 15000) == 0);
    CHECK(mt_btp_closed(&B) && mt_btp_error(&B) == MT_ERR_TIMEOUT);
    /* a data packet */
    hs(23, 5);
    poll(0);
    CHECK(WR(1000, 0x08, 0x00, 0x00) == MT_OK);
    CHECK(mt_btp_send(&B, mt_span_of(m, 3)) == MT_OK);
    CHECK(poll(1000) > 0);
    CHECK(mt_btp_wait_ms(&B, 1000) == MT_BTP_ACK_WAIT_MS);
    CHECK(mt_btp_wait_ms(&B, 1000 + 14999) == 1);
    CHECK(poll(1000 + 14999) == 0 && mt_btp_open(&B));
    CHECK(mt_btp_wait_ms(&B, 1000 + 15000) == 0);
    CHECK(poll(1000 + 15000) == 0);
    CHECK(mt_btp_closed(&B) && mt_btp_error(&B) == MT_ERR_TIMEOUT);
    /* clock wrap-around */
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    CHECK(WR(0xFFFFFF00u, 0x65, 0x6C, 0x04, 0, 0, 0, 23, 0, 5) == MT_OK);
    poll(0xFFFFFF00u);
    CHECK(WR(0xFFFFFF80u, 0x08, 0x00, 0x00) == MT_OK);
    CHECK(poll(0xFFFFFF80u + 2499) == 0);
    CHECK(poll(0xFFFFFF80u + 2500) == 3);
}

static void test_sequence_wrap(void)
{
    uint8_t m[5] = { 9, 8, 7, 6, 5 }, cseq = 0;
    int i;
    hs(23, 5);
    poll(0);
    for (i = 0; i < 600; i++) { /* both 8-bit counters wrap more than twice */
        uint8_t ours;
        size_t n;
        CHECK(mt_btp_send(&B, mt_span_of(m, 5)) == MT_OK);
        n = poll(10);
        CHECK(n == 9 || n == 10); /* ack piggybacked once we have received anything */
        ours = pk[(pk[0] & 8) ? 2 : 1];
        CHECK(WR(10, 0x08, ours, cseq++) == MT_OK);
        CHECK(poll(10) == 0);
    }
    CHECK(mt_btp_open(&B));
    {   /* and an inbound message after the wrap */
        CHECK(WR(11, 0x05, cseq++, 0x01, 0x00, 0x42) == MT_OK);
        CHECK(mt_btp_msg(&B).len == 1);
    }
}


/* Peripheral engine against a central engine (mt_btp_central_open): both directions, large messages, small and
 * large MTU, packets carried one at a time like GATT writes and indications. */
/* The central reports 247, the link negotiated 100: the response offers 97. */
static void test_limit_mtu(void)
{
    uint8_t req[MT_BTP_HS_REQ_LEN];
    size_t n;
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    n = mt_btp_hs_request(req, 247, 4);
    CHECK(wr(0, req, n) == MT_OK);
    mt_btp_limit_mtu(&B, 100);
    n = poll(0);
    CHECK(n == 6 && mt_get_le16(pk + 3) == 97 && mt_btp_frag_size(&B) == 97);
    mt_btp_limit_mtu(&B, 0); /* nonsense MTUs clamp to the minimum segment */
    CHECK(mt_btp_frag_size(&B) == MT_BTP_MIN_FRAG);
}

/* An idle link between two engines stays up: standalone acks are acked in turn (a keep-alive every 2.5 s). */
static void test_idle_keepalive(uint8_t window)
{
    static uint8_t crx[64];
    mt_btp C;
    uint8_t req[MT_BTP_HS_REQ_LEN], cpk[256];
    unsigned pkts = 0;
    size_t n;
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    n = mt_btp_hs_request(req, 247, window);
    CHECK(wr(0, req, n) == MT_OK);
    n = poll(0);
    CHECK(n == 6 && mt_btp_central_open(&C, mt_buf_of(crx, sizeof crx), 0, mt_span_of(pk, n)) == MT_OK);
    for (uint32_t t = 0; t <= 60000; t += 100) {
        size_t a = mt_btp_poll(&C, t, mt_buf_of(cpk, sizeof cpk));
        if (a) { pkts++; CHECK(mt_btp_rx(&B, t, mt_span_of(cpk, a)) == MT_OK); }
        size_t b = poll(t);
        if (b) { pkts++; CHECK(mt_btp_rx(&C, t, mt_span_of(pk, b)) == MT_OK); }
    }
    CHECK(mt_btp_open(&B) && mt_btp_open(&C));
    CHECK(pkts >= 20 && pkts <= 30);   /* one standalone ack per 2.5 s, alternating sides (also window 1 / 2) */
}

/* Window 2: the peer's data is acked at once (its window is down to the ack slot), its standalone ack only by the
 * keep-alive timer; acking every ack at once would ping-pong on an idle link. */
static void test_small_window_acks(void)
{
    hs(23, 2);
    poll(0);
    CHECK(WR(10, 0x0D, 0x00, 0x00, 0x01, 0x00, 0xAA) == MT_OK);   /* S|E, acks our response, seq 0, 1 byte */
    {
        size_t n = poll(10);
        CHECK_BYTES(pk, n, 0x08, 0x00, 0x01);                      /* immediate standalone ack, our seq 1 */
    }
    mt_btp_msg_release(&B);
    CHECK(WR(20, 0x08, 0x01, 0x01) == MT_OK);                      /* the peer acks our ack (seq 1) */
    CHECK(poll(20) == 0);                                          /* not at once ... */
    CHECK(mt_btp_wait_ms(&B, 20) == MT_BTP_ACK_SEND_MS);
    CHECK(poll(20 + MT_BTP_ACK_SEND_MS - 1) == 0);
    {
        size_t n = poll(20 + MT_BTP_ACK_SEND_MS);                  /* ... but by the timer */
        CHECK_BYTES(pk, n, 0x08, 0x01, 0x02);
    }
    /* window 1: same */
    hs(23, 1);
    poll(0);
    CHECK(WR(10, 0x08, 0x00, 0x00) == MT_OK);                      /* standalone ack of our response, seq 0 */
    CHECK(poll(10) == 0);
    CHECK(poll(10 + MT_BTP_ACK_SEND_MS) > 0);
}

static void test_peer(uint16_t mtu, uint8_t win, size_t len)
{
    static uint8_t crx[1300], m1[1300], m2[1300];
    mt_btp C;
    uint8_t req[MT_BTP_HS_REQ_LEN], cpk[256];
    size_t n, i;
    uint32_t t = 0;
    int guard = 0, got_c = 0, got_p = 0;
    for (i = 0; i < len; i++) { m1[i] = (uint8_t)(i * 3 + 1); m2[i] = (uint8_t)(i * 5 + 7); }
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    n = mt_btp_hs_request(req, mtu, win);
    CHECK(wr(t, req, n) == MT_OK);
    n = poll(t);
    CHECK(n == 6 && mt_btp_central_open(&C, mt_buf_of(crx, sizeof crx), t, mt_span_of(pk, n)) == MT_OK);
    CHECK(mt_btp_frag_size(&C) == mt_btp_frag_size(&B));
    CHECK(mt_btp_send(&C, mt_span_of(m1, len)) == MT_OK);   /* central -> peripheral */
    CHECK(mt_btp_send(&B, mt_span_of(m2, len)) == MT_OK);   /* and the other way at the same time */
    while (guard++ < 2000 && !(got_c && got_p)) {
        size_t a = mt_btp_poll(&C, t, mt_buf_of(cpk, sizeof cpk));
        if (a) CHECK(mt_btp_rx(&B, t, mt_span_of(cpk, a)) == MT_OK);
        size_t b = poll(t);
        if (b) CHECK(mt_btp_rx(&C, t, mt_span_of(pk, b)) == MT_OK);
        if (mt_btp_msg(&B).len) {
            CHECK(mt_btp_msg(&B).len == len && memcmp(mt_btp_msg(&B).p, m1, len) == 0);
            mt_btp_msg_release(&B);
            got_p = 1;
        }
        if (mt_btp_msg(&C).len) {
            CHECK(mt_btp_msg(&C).len == len && memcmp(mt_btp_msg(&C).p, m2, len) == 0);
            mt_btp_msg_release(&C);
            got_c = 1;
        }
        if (!a && !b) t += 100;   /* idle: let the ack timers run */
    }
    CHECK(got_c && got_p && mt_btp_open(&B) && mt_btp_open(&C));
    CHECK(WR(0, 0x65, 0x6C, 0x04, 0, 0, 0, 0, 0, 5) == MT_ERR_STATE || mt_btp_closed(&B)); /* no second handshake */
    CHECK(mt_btp_central_open(&C, mt_buf_of(crx, sizeof crx), 0, mt_span_of(req, 6)) == MT_ERR_INVALID);
}

/* Regression: the opening seen from iOS 27. The request is unnumbered, so its first write after our response is
 * "0d 00 00 62 00 ..": Start|End|Ack, ack 0 (our response), seq 0, 98 bytes. Our reply acks 0 and is our seq 1. */
static void test_ios_opening(void)
{
    uint8_t w[5 + 0x62], m[0x62];
    const uint8_t reply[] = { 0xA1, 0xB2, 0xC3 };
    size_t n, i;
    for (i = 0; i < sizeof m; i++) m[i] = (uint8_t)(0x15 + i * 11);
    mt_btp_init(&B, mt_buf_of(rxmem, sizeof rxmem), 0);
    CHECK(WR(0, 0x65, 0x6C, 0x04, 0x00, 0x00, 0x00, 0xF7, 0x00, 0x06) == MT_OK); /* MTU 247, window 6 */
    n = poll(0);
    CHECK_BYTES(pk, n, 0x65, 0x6C, 0x04, 0xF4, 0x00, 0x05);
    CHECK(poll(0) == 0);
    w[0] = 0x0D; w[1] = 0x00; w[2] = 0x00; w[3] = 0x62; w[4] = 0x00;
    memcpy(w + 5, m, sizeof m);
    CHECK(wr(40, w, sizeof w) == MT_OK);
    CHECK(mt_btp_open(&B));
    CHECK(mt_btp_msg(&B).len == sizeof m && memcmp(mt_btp_msg(&B).p, m, sizeof m) == 0);
    CHECK(mt_btp_wait_ms(&B, 40) == MT_BTP_ACK_SEND_MS); /* our response is acked, its seq 0 is owed */
    mt_btp_msg_release(&B);
    CHECK(mt_btp_send(&B, mt_span_of(reply, sizeof reply)) == MT_OK);
    n = poll(50);
    CHECK_BYTES(pk, n, 0x0D, 0x00, 0x01, 0x03, 0x00, 0xA1, 0xB2, 0xC3);
    CHECK(WR(60, 0x08, 0x01, 0x01) == MT_OK); /* iOS acks our seq 1 with its seq 1 */
    CHECK(mt_btp_open(&B));
}

int main(void)
{
    test_handshake();
    test_ios_opening();
    test_ack_timer_and_single_message();
    test_receive();
    test_send();
    test_window_limit();
    test_window_one_and_two();
    test_immediate_ack();
    test_errors();
    test_ack_timeout();
    test_sequence_wrap();
    test_limit_mtu();
    test_idle_keepalive(4);
    test_idle_keepalive(2);
    test_idle_keepalive(1);
    test_small_window_acks();
    test_peer(247, 5, 1200);
    test_peer(23, 3, 700);
    test_peer(185, 2, 1);
    printf("btp: %d checks, %d failures\n", checks, fails);
    return fails != 0;
}
