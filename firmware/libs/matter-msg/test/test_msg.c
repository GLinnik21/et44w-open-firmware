/* Host tests for matter-msg. Vector sources:
 *  - Message header encodings: connectedhomeip src/transport/raw/tests/TestMessageHeader.cpp
 *    (theSpecComplianceTestVector, theTestVectorMsgExtensions).
 *  - Encrypted frames: rs-matter rs-matter/src/transport/proto_hdr.rs tests test_decrypt_success and
 *    test_encrypt_success, both "captured from an execution run of the chip-tool binary".
 *  - Window behaviour follows spec 4.6.5; the window is 32 wide, bit i of `seen` = counter max-1-i. */
#include <stdio.h>
#include <string.h>

#include "mt_msg.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static size_t unhex(const char *s, uint8_t *out)
{
    size_t n = 0;
    unsigned v;
    while (s[0] && s[1]) { sscanf(s, "%2x", &v); out[n++] = (uint8_t)v; s += 2; }
    return n;
}

static int eqhex(const uint8_t *got, size_t len, const char *hex)
{
    uint8_t want[256];
    return unhex(hex, want) == len && memcmp(got, want, len) == 0;
}

static mt_err dec(const char *hex, mt_msg_hdr *h, size_t *used)
{
    uint8_t b[64];
    size_t n = unhex(hex, b);
    return mt_msg_hdr_decode(mt_span_of(b, n), h, used);
}

static void test_hdr_spec_vectors(void)
{
    mt_msg_hdr h;
    size_t used;
    uint8_t out[MT_MSG_HDR_MAX];

    /* secure unicast */
    CHECK(dec("0088770044332211", &h, &used) == MT_OK);
    CHECK(used == 8 && h.session_id == 0x7788 && h.sec_flags == 0 && h.counter == 0x11223344);
    CHECK(!h.has_src && h.dsiz == MT_MSG_DSIZ_NONE);
    CHECK(mt_msg_hdr_encode(&h, mt_buf_of(out, sizeof out), &used) == MT_OK && eqhex(out, used, "0088770044332211"));

    /* unsecured */
    CHECK(dec("0000000040302010", &h, &used) == MT_OK && h.session_id == 0 && h.counter == 0x10203040);

    /* secure group, with C and P flags (0xC1): privacy is rejected */
    CHECK(dec("02EEDDC1403020105634", &h, &used) == MT_ERR_UNSUPPORTED);
    /* the same without P (0x41): decodes, but group sessions are not ours to seal/open */
    CHECK(dec("02EEDD41403020105634", &h, &used) == MT_OK);
    CHECK(used == 10 && h.session_id == 0xDDEE && h.sec_flags == 0x41 && h.dsiz == MT_MSG_DSIZ_GROUP && h.dst == 0x3456);
    CHECK(mt_msg_hdr_encode(&h, mt_buf_of(out, sizeof out), &used) == MT_OK && eqhex(out, used, "02EEDD41403020105634"));
}

static void test_hdr_extensions(void)
{
    /* connectedhomeip theTestVectorMsgExtensions: MX skip, with src/dst combinations; the protocol
     * header follows at the returned offset. */
    static const struct { const char *hex; size_t used; uint8_t dsiz; int src; } v[] = {
        { "00000020CCCCCCCC0400E4E3E2E1", 14, 0, 0 },
        { "04000020CCCCCCCC11111111111111110400E4E3E2E1", 22, 0, 1 },
        { "01000020CCCCCCCCDDDDDDDDDDDDDDDD0400E4E3E2E1", 22, 1, 0 },
        { "05000020CCCCCCCC1111111111111111DDDDDDDDDDDDDDDD0400E4E3E2E1", 30, 1, 1 },
        { "02000021CCCCCCCCDDDD0400E4E3E2E1", 16, 2, 0 },
        { "06000021CCCCCCCC1111111111111111DDDD0400E4E3E2E1", 24, 2, 1 },
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        mt_msg_hdr h;
        size_t used;
        CHECK(dec(v[i].hex, &h, &used) == MT_OK);
        CHECK(used == v[i].used && h.dsiz == v[i].dsiz && h.has_src == v[i].src && h.counter == 0xCCCCCCCC);
        CHECK(h.sec_flags & MT_MSG_SEC_EXT);
    }
    /* extension length runs past the buffer */
    CHECK(dec("00000020CCCCCCCC0400E4E3", &(mt_msg_hdr){0}, &(size_t){0}) == MT_ERR_INVALID);
}

static void test_hdr_round_trip(void)
{
    mt_msg_hdr in = { .session_id = 0xBEEF, .sec_flags = MT_MSG_SEC_CONTROL, .counter = 0xDEADBEEF,
                      .has_src = true, .src = 0x0102030405060708ull, .dsiz = MT_MSG_DSIZ_NODE,
                      .dst = 0x1122334455667788ull };
    mt_msg_hdr out;
    uint8_t b[MT_MSG_HDR_MAX];
    size_t used, used2;
    CHECK(mt_msg_hdr_encode(&in, mt_buf_of(b, sizeof b), &used) == MT_OK && used == 24);
    CHECK(mt_msg_hdr_decode(mt_span_of(b, used), &out, &used2) == MT_OK && used2 == used);
    CHECK(out.session_id == in.session_id && out.sec_flags == in.sec_flags && out.counter == in.counter);
    CHECK(out.has_src && out.src == in.src && out.dsiz == MT_MSG_DSIZ_NODE && out.dst == in.dst);

    in.dsiz = MT_MSG_DSIZ_GROUP;
    in.dst = 0xABCD;
    in.has_src = false;
    CHECK(mt_msg_hdr_encode(&in, mt_buf_of(b, sizeof b), &used) == MT_OK && used == 10);
    CHECK(mt_msg_hdr_decode(mt_span_of(b, used), &out, &used2) == MT_OK && out.dsiz == MT_MSG_DSIZ_GROUP && out.dst == 0xABCD);

    /* every prefix of a valid header is rejected */
    for (size_t n = 0; n < used; n++) CHECK(mt_msg_hdr_decode(mt_span_of(b, n), &out, &used2) == MT_ERR_INVALID);

    /* encode refusals */
    CHECK(mt_msg_hdr_encode(&in, mt_buf_of(b, 9), &used) == MT_ERR_BUFFER_TOO_SMALL);
    in.sec_flags = MT_MSG_SEC_PRIVACY;
    CHECK(mt_msg_hdr_encode(&in, mt_buf_of(b, sizeof b), &used) == MT_ERR_UNSUPPORTED);
    in.sec_flags = MT_MSG_SEC_EXT;
    CHECK(mt_msg_hdr_encode(&in, mt_buf_of(b, sizeof b), &used) == MT_ERR_UNSUPPORTED);
    in.sec_flags = 0;
    in.dsiz = 3;
    CHECK(mt_msg_hdr_encode(&in, mt_buf_of(b, sizeof b), &used) == MT_ERR_INVALID);

    /* decode refusals: version 1, DSIZ 3, session type 2 */
    CHECK(dec("1000000000000000", &out, &used) == MT_ERR_UNSUPPORTED);
    CHECK(dec("0300000000000000", &out, &used) == MT_ERR_INVALID);
    CHECK(dec("0000000200000000", &out, &used) == MT_ERR_INVALID);
}

static void test_proto_hdr(void)
{
    /* chip-tool frame plaintext prefix: I|R, opcode 8, exchange 0x0070, protocol 1 (IM) */
    uint8_t b[MT_PROTO_HDR_MAX];
    mt_proto_hdr h, o;
    size_t used;
    CHECK(mt_proto_hdr_decode(mt_span_of((uint8_t *)"\x05\x08\x70\x00\x01\x00\x15", 7), &h, &used) == MT_OK);
    CHECK(used == 6 && h.flags == (MT_XCHG_INITIATOR | MT_XCHG_RELIABLE) && h.opcode == 8 && h.exchange_id == 0x70);
    CHECK(h.protocol_id == 1 && h.vendor_id == 0);
    CHECK(mt_proto_hdr_encode(&h, mt_buf_of(b, sizeof b), &used) == MT_OK && eqhex(b, used, "050870000100"));

    /* all fields: ack + vendor */
    h = (mt_proto_hdr){ .flags = MT_XCHG_ACK | MT_XCHG_RELIABLE, .opcode = 0x40, .exchange_id = 0xA1B2,
                        .vendor_id = 0xFFF1, .protocol_id = 0x0000, .ack_counter = 0x01020304 };
    CHECK(mt_proto_hdr_encode(&h, mt_buf_of(b, sizeof b), &used) == MT_OK && used == 12);
    CHECK(eqhex(b, used, "1640B2A1F1FF000004030201"));
    CHECK(mt_proto_hdr_decode(mt_span_of(b, used), &o, &used) == MT_OK && used == 12);
    CHECK(o.flags == (MT_XCHG_ACK | MT_XCHG_RELIABLE | MT_XCHG_VENDOR) && o.vendor_id == 0xFFF1 && o.ack_counter == 0x01020304);
    CHECK(o.opcode == 0x40 && o.exchange_id == 0xA1B2 && o.protocol_id == 0);
    for (size_t n = 0; n < 12; n++) CHECK(mt_proto_hdr_decode(mt_span_of(b, n), &o, &(size_t){0}) == MT_ERR_INVALID);
    CHECK(mt_proto_hdr_encode(&h, mt_buf_of(b, 11), &used) == MT_ERR_BUFFER_TOO_SMALL);

    /* connectedhomeip protocol-header vectors with secured extensions: SX block skipped */
    {
        uint8_t m[] = { 0x08, 0xCC, 0xEE, 0xEE, 0x66, 0x66, 0x04, 0x00, 0xE4, 0xE3, 0xE2, 0xE1, 0xBB, 0xBB };
        CHECK(mt_proto_hdr_decode(mt_span_of(m, sizeof m), &o, &used) == MT_OK && used == 12);
        CHECK(o.protocol_id == 0x6666 && o.exchange_id == 0xEEEE && o.opcode == 0xCC);
        uint8_t v[] = { 0x01, 0xCC, 0xEE, 0xEE, 0x66, 0x66, 0xBB, 0xBB };
        CHECK(mt_proto_hdr_decode(mt_span_of(v, sizeof v), &o, &used) == MT_OK && used == 6);
        o.flags |= MT_XCHG_SECEXT;
        CHECK(mt_proto_hdr_encode(&o, mt_buf_of(b, sizeof b), &used) == MT_ERR_UNSUPPORTED);
    }
}

static const char *KEY1 = "66633197439c17b97e10ee47c808804a";
static const char *KEY2 = "44d43c91d227f3ba0824c5d87cb81b33";
static const char *CAPTURED_FRAME =
    "00020000f243e90031b566ec8b5bf417e480f3d5115919b5239135370bf9bf69551175877719fcf35d4b471fb05ebeb5"
    "10adc6789450e5d2e080efa83af0a6af1b0235a7d1c632";
static const char *CAPTURED_PLAIN =
    "050870000100152800280136021537002400002401302402021835012400002c010257572402032503b80b18181818";

static void key_of(const char *hex, uint8_t k[16])
{
    unhex(hex, k);
}

static void test_chip_tool_vectors(void)
{
    uint8_t key[16], f[96];
    mt_msg_hdr h;
    size_t len = unhex(CAPTURED_FRAME, f), off, plen;

    key_of(KEY1, key);
    CHECK(len == 71);
    CHECK(mt_msg_open(key, 0, f, len, &h, &off, &plen) == MT_OK);
    CHECK(h.session_id == 2 && h.counter == 15287282 && off == 8 && plen == 47);
    CHECK(eqhex(f + off, plen, CAPTURED_PLAIN));

    /* tampering: tag, ciphertext, header (AAD), counter (nonce), wrong key, short frame */
    for (int t = 0; t < 4; t++) {
        len = unhex(CAPTURED_FRAME, f);
        if (t == 0) f[len - 1] ^= 1;
        if (t == 1) f[20] ^= 1;
        if (t == 2) f[1] ^= 1;
        if (t == 3) f[4] ^= 1;
        CHECK(mt_msg_open(key, 0, f, len, &h, &off, &plen) == MT_ERR_CRYPTO);
    }
    len = unhex(CAPTURED_FRAME, f);
    CHECK(mt_msg_open(key, 1, f, len, &h, &off, &plen) == MT_ERR_CRYPTO); /* wrong peer node => wrong nonce */
    key[0] ^= 1;
    CHECK(mt_msg_open(key, 0, f, len, &h, &off, &plen) == MT_ERR_CRYPTO);
    key[0] ^= 1;
    CHECK(mt_msg_open(key, 0, f, 8 + 15, &h, &off, &plen) == MT_ERR_INVALID);
    CHECK(mt_msg_open(key, 0, f, 8 + 16, &h, &off, &plen) == MT_ERR_CRYPTO);
    /* the same frame through an already decoded header */
    len = unhex(CAPTURED_FRAME, f);
    CHECK(mt_msg_hdr_decode(mt_span_of(f, len), &h, &off) == MT_OK && off == 8);
    plen = 0;
    CHECK(mt_msg_open_decoded(key, 0, f, len, &h, off, &plen) == MT_OK && plen == 47);
    CHECK(eqhex(f + off, plen, CAPTURED_PLAIN));
    CHECK(mt_msg_open_decoded(key, 0, f, 8 + 15, &h, 8, &plen) == MT_ERR_INVALID);

    /* chip-tool encrypt vector: counter 41, session 0x11, key2, source node 0 */
    {
        uint8_t k2[16], fr[80];
        size_t hl = unhex("0011000029000000", fr), flen;
        size_t pl = unhex("05085828010015360015370024000124020624030118350118181818", fr + hl);
        mt_msg_hdr sh;
        CHECK(pl == 28);
        key_of(KEY2, k2);
        CHECK(mt_msg_hdr_decode(mt_span_of(fr, hl), &sh, &(size_t){0}) == MT_OK);
        CHECK(mt_msg_seal(k2, 0, &sh, mt_buf_of(fr, sizeof fr), hl, pl, &flen) == MT_OK && flen == 52);
        CHECK(eqhex(fr + hl, 44, "bd53fa7926576111994ef314240b838e88a5e36bcc81c1992a838afe16be4cf4742d9cd7e582d793491558d8"));
        CHECK(mt_msg_seal(k2, 0, &sh, mt_buf_of(fr, 51), hl, pl, &flen) == MT_ERR_BUFFER_TOO_SMALL);
    }
}

static void test_seal_open_round_trip(void)
{
    uint8_t key[16], f[128];
    mt_msg_hdr h = { .session_id = 0x1234, .sec_flags = 0, .counter = 0x01020304, .has_src = true,
                     .src = 0xAABBCCDDEEFF0011ull, .dsiz = MT_MSG_DSIZ_NODE, .dst = 0x55 }, g;
    mt_proto_hdr p = { .flags = MT_XCHG_INITIATOR, .opcode = 2, .exchange_id = 9, .protocol_id = 0x0001 };
    size_t hl, pl, len, off, plen, used;
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 7 + 1);

    CHECK(mt_msg_hdr_encode(&h, mt_buf_of(f, sizeof f), &hl) == MT_OK);
    CHECK(mt_proto_hdr_encode(&p, mt_buf_of(f + hl, sizeof f - hl), &pl) == MT_OK);
    memcpy(f + hl + pl, "hello", 5);
    pl += 5;
    CHECK(mt_msg_seal(key, 0, &h, mt_buf_of(f, sizeof f), hl, pl, &len) == MT_ERR_INVALID); /* header source != nonce source */
    CHECK(mt_msg_seal(key, h.src, &h, mt_buf_of(f, sizeof f), hl, pl, &len) == MT_OK && len == hl + pl + 16);
    CHECK(memcmp(f + hl + pl - 5, "hello", 5) != 0); /* really encrypted */

    /* source node comes from the header when present: peer_node argument is irrelevant */
    CHECK(mt_msg_open(key, 0, f, len, &g, &off, &plen) == MT_OK);
    CHECK(off == hl && plen == pl && g.counter == h.counter && g.src == h.src);
    CHECK(mt_proto_hdr_decode(mt_span_of(f + off, plen), &p, &used) == MT_OK && used == 6);
    CHECK(memcmp(f + off + used, "hello", 5) == 0);

    /* group sessions and privacy are refused */
    h.sec_flags = 1;
    CHECK(mt_msg_seal(key, 0, &h, mt_buf_of(f, sizeof f), hl, pl, &len) == MT_ERR_UNSUPPORTED);
    f[3] = 0x80;
    CHECK(mt_msg_open(key, 0, f, 60, &g, &off, &plen) == MT_ERR_UNSUPPORTED);

    /* empty payload: header + MIC only */
    h.sec_flags = 0;
    CHECK(mt_msg_hdr_encode(&h, mt_buf_of(f, sizeof f), &hl) == MT_OK);
    CHECK(mt_msg_seal(key, h.src, &h, mt_buf_of(f, sizeof f), hl, 0, &len) == MT_OK && len == hl + 16);
    CHECK(mt_msg_open(key, 0, f, len, &g, &off, &plen) == MT_OK && plen == 0);
}

static void test_rx_secure(void)
{
    mt_msg_rx rx;
    mt_msg_rx_init(&rx);
    /* first counter seeds the window; everything below counts as seen */
    CHECK(mt_msg_rx_accept(&rx, 1000, MT_MSG_RX_SECURE) == MT_OK);
    CHECK(mt_msg_rx_accept(&rx, 1000, MT_MSG_RX_SECURE) == MT_ERR_DUPLICATE);
    CHECK(mt_msg_rx_accept(&rx, 999, MT_MSG_RX_SECURE) == MT_ERR_DUPLICATE);
    CHECK(mt_msg_rx_accept(&rx, 900, MT_MSG_RX_SECURE) == MT_ERR_STALE);
    /* jump by 5: 1001..1004 are unseen, 1000 is seen */
    CHECK(mt_msg_rx_accept(&rx, 1005, MT_MSG_RX_SECURE) == MT_OK);
    CHECK(mt_msg_rx_accept(&rx, 1000, MT_MSG_RX_SECURE) == MT_ERR_DUPLICATE);
    CHECK(mt_msg_rx_accept(&rx, 1003, MT_MSG_RX_SECURE) == MT_OK);   /* reordered, fresh */
    CHECK(mt_msg_rx_accept(&rx, 1003, MT_MSG_RX_SECURE) == MT_ERR_DUPLICATE);
    CHECK(mt_msg_rx_accept(&rx, 1001, MT_MSG_RX_SECURE) == MT_OK);
    CHECK(mt_msg_rx_accept(&rx, 1002, MT_MSG_RX_SECURE) == MT_OK);
    CHECK(mt_msg_rx_accept(&rx, 1004, MT_MSG_RX_SECURE) == MT_OK);
    CHECK(mt_msg_rx_accept(&rx, 1004, MT_MSG_RX_SECURE) == MT_ERR_DUPLICATE);
    /* window edge: max 1005, the 32nd counter below is 973 */
    CHECK(mt_msg_rx_accept(&rx, 1005 + 20, MT_MSG_RX_SECURE) == MT_OK);   /* max 1025, 1005 seen at bit 19 */
    CHECK(mt_msg_rx_accept(&rx, 1005, MT_MSG_RX_SECURE) == MT_ERR_DUPLICATE);
    CHECK(mt_msg_rx_accept(&rx, 1024, MT_MSG_RX_SECURE) == MT_OK);        /* skipped by the jump, still fresh */
    CHECK(mt_msg_rx_accept(&rx, 1025 - 32, MT_MSG_RX_SECURE) == MT_ERR_DUPLICATE); /* 993: 32 below max, seeded as seen */
}

static void test_rx_window_edges(void)
{
    mt_msg_rx rx;
    mt_msg_rx_init(&rx);
    CHECK(mt_msg_rx_accept(&rx, 100, MT_MSG_RX_SECURE) == MT_OK);
    /* exact jump of 32: old max (100) is bit 31, 101..131 are unseen */
    CHECK(mt_msg_rx_accept(&rx, 132, MT_MSG_RX_SECURE) == MT_OK);
    CHECK(mt_msg_rx_accept(&rx, 100, MT_MSG_RX_SECURE) == MT_ERR_DUPLICATE);
    CHECK(mt_msg_rx_accept(&rx, 101, MT_MSG_RX_SECURE) == MT_OK);   /* 31 below max: in window, unseen */
    CHECK(mt_msg_rx_accept(&rx, 131, MT_MSG_RX_SECURE) == MT_OK);
    CHECK(mt_msg_rx_accept(&rx, 99, MT_MSG_RX_SECURE) == MT_ERR_STALE); /* 33 below: outside */
    /* a jump past the window marks the skipped counters as seen (conservative) */
    CHECK(mt_msg_rx_accept(&rx, 132 + 33, MT_MSG_RX_SECURE) == MT_OK);
    CHECK(mt_msg_rx_accept(&rx, 140, MT_MSG_RX_SECURE) == MT_ERR_DUPLICATE);
    CHECK(mt_msg_rx_accept(&rx, 164, MT_MSG_RX_SECURE) == MT_ERR_DUPLICATE);
    /* no rollover for secure sessions: a small counter after a huge one is old */
    mt_msg_rx_init(&rx);
    CHECK(mt_msg_rx_accept(&rx, 0xFFFFFFF0u, MT_MSG_RX_SECURE) == MT_OK);
    CHECK(mt_msg_rx_accept(&rx, 5, MT_MSG_RX_SECURE) == MT_ERR_STALE);
    CHECK(mt_msg_rx_accept(&rx, 0xFFFFFFFFu, MT_MSG_RX_SECURE) == MT_OK);
}

static void test_rx_unsecured(void)
{
    mt_msg_rx rx;
    mt_msg_rx_init(&rx);
    CHECK(mt_msg_rx_accept(&rx, 0xFFFFFFFEu, MT_MSG_RX_UNSECURED) == MT_OK);
    CHECK(mt_msg_rx_accept(&rx, 2, MT_MSG_RX_UNSECURED) == MT_OK);          /* rolled over: forward by 4 */
    CHECK(mt_msg_rx_accept(&rx, 0xFFFFFFFFu, MT_MSG_RX_UNSECURED) == MT_OK); /* reordered, in window */
    CHECK(mt_msg_rx_accept(&rx, 0xFFFFFFFFu, MT_MSG_RX_UNSECURED) == MT_ERR_DUPLICATE);
    CHECK(mt_msg_rx_accept(&rx, 2, MT_MSG_RX_UNSECURED) == MT_ERR_DUPLICATE);
    /* far behind (peer rebooted with a new random counter): resync */
    CHECK(mt_msg_rx_accept(&rx, 0x40000000u, MT_MSG_RX_UNSECURED) == MT_OK);
    CHECK(mt_msg_rx_accept(&rx, 0x40000000u + 0x90000000u, MT_MSG_RX_UNSECURED) == MT_OK); /* backwards by 2^31+: resync */
    CHECK(mt_msg_rx_accept(&rx, 0x40000000u + 0x90000001u, MT_MSG_RX_UNSECURED) == MT_OK);
}

static void test_tx(void)
{
    mt_msg_tx tx;
    uint32_t c;
    mt_msg_tx_init(&tx, 0xFFFFFFFFu, true);
    CHECK(tx.next == 0x0FFFFFFF);          /* start is a 28-bit value */
    CHECK(mt_msg_tx_next(&tx, &c) == MT_OK && c == 0x0FFFFFFF);
    CHECK(mt_msg_tx_next(&tx, &c) == MT_OK && c == 0x10000000);

    mt_msg_tx_init(&tx, 0, true);
    tx.next = 0xFFFFFFFEu;
    CHECK(mt_msg_tx_next(&tx, &c) == MT_OK && c == 0xFFFFFFFEu);
    CHECK(mt_msg_tx_next(&tx, &c) == MT_OK && c == 0xFFFFFFFFu);
    CHECK(mt_msg_tx_next(&tx, &c) == MT_ERR_STATE);       /* secure counters never repeat */
    CHECK(mt_msg_tx_next(&tx, &c) == MT_ERR_STATE);

    mt_msg_tx_init(&tx, 0, false);
    tx.next = 0xFFFFFFFFu;
    CHECK(mt_msg_tx_next(&tx, &c) == MT_OK && c == 0xFFFFFFFFu);
    CHECK(mt_msg_tx_next(&tx, &c) == MT_OK && c == 0);    /* the unsecured counter wraps */
}

int main(void)
{
    test_hdr_spec_vectors();
    test_hdr_extensions();
    test_hdr_round_trip();
    test_proto_hdr();
    test_chip_tool_vectors();
    test_seal_open_round_trip();
    test_rx_secure();
    test_rx_window_edges();
    test_rx_unsecured();
    test_tx();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
