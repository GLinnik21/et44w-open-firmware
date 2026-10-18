/* BTP engine, peripheral side. Layout and rules follow Matter spec 4.19 and connectedhomeip BtpEngine (the
 * peripheral's Init(expect_first_ack = true)): our handshake response is our sequence number 0 and waits for an
 * ack, so our first data packet is 1; the central's request is not numbered, its first packet is 0 and acks our 0.
 * Seen from iOS 27 (first write "0d 00 00 ..": ack 0, seq 0) and matter.js BtpSessionHandler. */
#include "mt_btp.h"

#include <string.h>

enum { F_START = 0x01, F_CONT = 0x02, F_END = 0x04, F_ACK = 0x08, F_DATA = 0x07 };
enum { HS_FLAGS = 0x65, HS_OPCODE = 0x6C, HS_RESP_LEN = 6, HS_VERSION = 4 };
enum { S_IDLE, S_OPEN, S_CLOSED };
enum { RX_IDLE, RX_BUSY, RX_READY };
enum { K_NONE, K_HS, K_DATA, K_ACK };

static mt_err fail(mt_btp *b, mt_err e)
{
    b->state = S_CLOSED;
    b->err = (uint8_t)e;
    return e;
}

void mt_btp_init(mt_btp *b, mt_buf rx, uint16_t fallback_mtu)
{
    memset(b, 0, sizeof *b);
    b->rx = rx;
    b->fallback_mtu = fallback_mtu ? fallback_mtu : 23;
}

static uint8_t out_count(const mt_btp *b)
{
    return b->tx_exp ? (uint8_t)(b->tx_newest - b->tx_oldest + 1) : 0;
}

/* Packets we may have outstanding: data leaves the last window slot for a standalone ack. */
static uint8_t data_limit(const mt_btp *b) { return b->window > 2 ? (uint8_t)(b->window - 1) : 1; }

/* Segment size for an ATT MTU: the MTU less the 3-byte ATT header, kept within the BTP limits. */
static uint8_t frag_for_mtu(unsigned att_mtu)
{
    unsigned n = att_mtu < MT_BTP_MIN_FRAG + 3 ? MT_BTP_MIN_FRAG : att_mtu - 3;
    return (uint8_t)(n > MT_BTP_MAX_FRAG ? MT_BTP_MAX_FRAG : n);
}

static mt_err on_handshake(mt_btp *b, mt_span p)
{
    unsigned mtu, i;
    bool ok = false;

    if (p.len < MT_BTP_HS_REQ_LEN || p.p[0] != HS_FLAGS || p.p[1] != HS_OPCODE)
        return fail(b, MT_ERR_INVALID);
    for (i = 0; i < 8; i++) { /* version nibbles, low nibble first, 0 ends the list */
        unsigned v = (p.p[2 + i / 2] >> ((i & 1) * 4)) & 0xF;
        if (v == 0)
            break;
        ok |= v == HS_VERSION;
    }
    if (!ok)
        return fail(b, MT_ERR_UNSUPPORTED);
    if (p.p[8] == 0)
        return fail(b, MT_ERR_INVALID);
    mtu = mt_get_le16(p.p + 6);
    if (mtu == 0)
        mtu = b->fallback_mtu;
    b->frag = frag_for_mtu(mtu);
    b->window = p.p[8] < MT_BTP_MAX_WINDOW ? p.p[8] : MT_BTP_MAX_WINDOW;
    b->state = S_OPEN;
    b->hs_pending = true;
    b->rx_next = 0;    /* the request carries no number */
    b->rx_pend = 0;
    b->rx_data = false;
    b->ack_due = false;
    return MT_OK;
}

/* Ack numbers must fall inside the unacked range [oldest, newest] (mod 256). */
static mt_err on_ack(mt_btp *b, uint32_t now, uint8_t ack)
{
    if (!b->tx_exp || (uint8_t)(ack - b->tx_oldest) > (uint8_t)(b->tx_newest - b->tx_oldest))
        return fail(b, MT_ERR_INVALID);
    if (ack == b->tx_newest) {
        b->tx_exp = false;
    } else {
        b->tx_oldest = (uint8_t)(ack + 1);
        b->wait_start = now;
    }
    return MT_OK;
}

/* Copy a fragment into the reassembly buffer and check the declared length. */
static mt_err on_payload(mt_btp *b, uint8_t flags, mt_span d)
{
    if (flags & F_START) {
        if (b->rx_state != RX_IDLE || (flags & F_CONT) || d.len < 2)
            return fail(b, b->rx_state == RX_READY ? MT_ERR_STATE : MT_ERR_INVALID);
        b->rx_len = mt_get_le16(d.p);
        b->rx_got = 0;
        d.p += 2;
        d.len -= 2;
        if (b->rx_len == 0)
            return fail(b, MT_ERR_INVALID);
        if (b->rx_len > b->rx.cap)
            return fail(b, MT_ERR_BUFFER_TOO_SMALL);
        b->rx_state = RX_BUSY;
    } else if (b->rx_state != RX_BUSY) {
        return fail(b, MT_ERR_INVALID);
    }
    if (d.len > (size_t)(b->rx_len - b->rx_got))
        return fail(b, MT_ERR_INVALID);
    memcpy(b->rx.p + b->rx_got, d.p, d.len);
    b->rx_got = (uint16_t)(b->rx_got + d.len);
    if ((flags & F_END) != (b->rx_got == b->rx_len ? F_END : 0))
        return fail(b, MT_ERR_INVALID); /* ended short, or full without End */
    if (flags & F_END)
        b->rx_state = RX_READY;
    return MT_OK;
}

static mt_err on_packet(mt_btp *b, uint32_t now, mt_span p)
{
    size_t i = 1;
    uint8_t flags = p.len ? p.p[0] : 0, seq;
    mt_err e;

    if ((flags & ~(F_DATA | F_ACK)) || p.len < 2)
        return fail(b, MT_ERR_INVALID);
    if (flags & F_ACK) {
        if (p.len < 3)
            return fail(b, MT_ERR_INVALID);
        e = on_ack(b, now, p.p[i++]);
        if (e != MT_OK)
            return e;
    }
    seq = p.p[i++];
    if (seq != b->rx_next)
        return fail(b, MT_ERR_INVALID); /* duplicate, skipped or out of order */
    b->rx_next++;
    b->rx_last = seq;
    b->rx_pend++;
    if (!(flags & F_DATA)) { /* standalone ack */
        e = (flags & F_ACK) ? MT_OK : fail(b, MT_ERR_INVALID);
    } else {
        e = on_payload(b, flags, mt_span_of(p.p + i, p.len - i));
        b->rx_data = true;
    }
    /* Every packet carries a sequence number and the sender times out without an ack (chip BtpEngine:
     * HasUnackedData counts standalone acks too), so a standalone ack is acked as well, but only by the timer
     * (next_kind): on an idle link this is a keep-alive exchange every MT_BTP_ACK_SEND_MS, also with a window of
     * 1 or 2, where an immediate ack of an ack would ping-pong once per connection event. */
    if (e == MT_OK && !b->ack_due) {
        b->ack_due = true;
        b->ack_since = now;
    }
    return e;
}

mt_err mt_btp_rx(mt_btp *b, uint32_t now_ms, mt_span pkt)
{
    if (b->state == S_CLOSED)
        return MT_ERR_STATE;
    if (b->state == S_IDLE)
        return on_handshake(b, pkt);
    if (pkt.len && (pkt.p[0] & 0x40))
        return fail(b, MT_ERR_STATE); /* second handshake */
    return on_packet(b, now_ms, pkt);
}

mt_span mt_btp_msg(const mt_btp *b)
{
    return b->rx_state == RX_READY ? mt_span_of(b->rx.p, b->rx_len) : mt_span_of(NULL, 0);
}

void mt_btp_msg_release(mt_btp *b)
{
    if (b->rx_state == RX_READY)
        b->rx_state = RX_IDLE;
}

mt_err mt_btp_send(mt_btp *b, mt_span msg)
{
    if (b->state != S_OPEN || b->tx.len)
        return MT_ERR_STATE;
    if (msg.len == 0 || msg.len > 0xFFFF)
        return MT_ERR_INVALID;
    b->tx = msg;
    b->tx_off = 0;
    return MT_OK;
}

bool mt_btp_tx_idle(const mt_btp *b) { return b->tx.len == 0; }

static bool ack_timer_due(const mt_btp *b, uint32_t now)
{
    return (uint32_t)(now - b->ack_since) >= MT_BTP_ACK_SEND_MS;
}

static int next_kind(const mt_btp *b, uint32_t now)
{
    uint8_t out = out_count(b);

    if (b->state != S_OPEN)
        return K_NONE;
    if (b->hs_pending)
        return K_HS;
    if (b->tx.len && out < data_limit(b))
        return K_DATA;
    /* Immediate ack once the peer's data fills its window less the slot kept for acks (chip: local receive window
     * <= 1); standalone acks alone wait for the timer. */
    if (b->ack_due && out < b->window && ((b->rx_data && b->rx_pend >= data_limit(b)) || ack_timer_due(b, now)))
        return K_ACK;
    return K_NONE;
}

static size_t emit_hs(mt_btp *b, uint32_t now, mt_buf out)
{
    if (out.cap < HS_RESP_LEN)
        return fail(b, MT_ERR_BUFFER_TOO_SMALL), 0;
    out.p[0] = HS_FLAGS;
    out.p[1] = HS_OPCODE;
    out.p[2] = HS_VERSION;
    mt_put_le16(out.p + 3, b->frag);
    out.p[5] = b->window;
    b->hs_pending = false;
    b->tx_next = 1;              /* the response is our 0 ... */
    b->tx_exp = true;            /* ... and the central's first packet acks it */
    b->tx_oldest = b->tx_newest = 0;
    b->wait_start = now;
    return HS_RESP_LEN;
}

/* Flags, piggybacked ack number (if we owe one) and sequence number. Returns the header length. */
static size_t put_header(mt_btp *b, uint32_t now, uint8_t *p, uint8_t flags)
{
    size_t n = 1;
    uint8_t seq = b->tx_next++;

    if (b->rx_pend) {
        flags |= F_ACK;
        p[n++] = b->rx_last;
        b->rx_pend = 0;
        b->rx_data = false;
        b->ack_due = false;
    }
    p[0] = flags;
    p[n++] = seq;
    if (!b->tx_exp) {
        b->tx_exp = true;
        b->tx_oldest = seq;
        b->wait_start = now;
    }
    b->tx_newest = seq;
    return n;
}

static size_t emit_data(mt_btp *b, uint32_t now, mt_buf out)
{
    bool first = b->tx_off == 0;
    size_t remain = b->tx.len - b->tx_off;
    size_t hdr = 2 + (b->rx_pend ? 1 : 0) + (first ? 2 : 0);
    size_t room = b->frag - hdr, n;
    bool last = remain <= room;
    uint8_t flags = (uint8_t)((first ? F_START : F_CONT) | (last ? F_END : 0));

    if (last)
        room = remain;
    if (!first && last)
        flags = F_END;
    n = put_header(b, now, out.p, flags);
    if (first) {
        mt_put_le16(out.p + n, (uint16_t)b->tx.len);
        n += 2;
    }
    memcpy(out.p + n, b->tx.p + b->tx_off, room);
    b->tx_off = (uint16_t)(b->tx_off + room);
    if (last)
        b->tx = mt_span_of(NULL, 0);
    return n + room;
}

size_t mt_btp_poll(mt_btp *b, uint32_t now_ms, mt_buf out)
{
    int k;

    if (b->state == S_OPEN && b->tx_exp && (uint32_t)(now_ms - b->wait_start) >= MT_BTP_ACK_WAIT_MS)
        return fail(b, MT_ERR_TIMEOUT), 0;
    k = next_kind(b, now_ms);
    if (k == K_NONE)
        return 0;
    if (k == K_HS)
        return emit_hs(b, now_ms, out);
    if (out.cap < b->frag)
        return fail(b, MT_ERR_BUFFER_TOO_SMALL), 0;
    if (k == K_DATA)
        return emit_data(b, now_ms, out);
    return put_header(b, now_ms, out.p, 0);
}

static uint32_t remaining(uint32_t since, uint32_t limit, uint32_t now)
{
    uint32_t el = now - since;
    return el >= limit ? 0 : limit - el;
}

uint32_t mt_btp_wait_ms(const mt_btp *b, uint32_t now_ms)
{
    uint32_t w = UINT32_MAX, t;

    if (b->state != S_OPEN)
        return w;
    if (next_kind(b, now_ms) != K_NONE)
        return 0;
    if (b->ack_due && out_count(b) < b->window)
        w = remaining(b->ack_since, MT_BTP_ACK_SEND_MS, now_ms);
    if (b->tx_exp) {
        t = remaining(b->wait_start, MT_BTP_ACK_WAIT_MS, now_ms);
        w = t < w ? t : w;
    }
    return w;
}

void mt_btp_limit_mtu(mt_btp *b, uint16_t att_mtu)
{
    uint8_t cap = frag_for_mtu(att_mtu);
    if (b->frag > cap) b->frag = cap;
}

bool mt_btp_open(const mt_btp *b) { return b->state == S_OPEN; }
bool mt_btp_closed(const mt_btp *b) { return b->state == S_CLOSED; }
mt_err mt_btp_error(const mt_btp *b) { return (mt_err)b->err; }
uint16_t mt_btp_frag_size(const mt_btp *b) { return b->frag; }

/* ---- central side (test peers) ---- */
size_t mt_btp_hs_request(uint8_t out[MT_BTP_HS_REQ_LEN], uint16_t mtu, uint8_t window)
{
    memset(out, 0, MT_BTP_HS_REQ_LEN);
    out[0] = HS_FLAGS;
    out[1] = HS_OPCODE;
    out[2] = HS_VERSION;
    mt_put_le16(out + 6, mtu);
    out[8] = window;
    return MT_BTP_HS_REQ_LEN;
}

mt_err mt_btp_central_open(mt_btp *b, mt_buf rx, uint32_t now_ms, mt_span r)
{
    uint16_t frag;

    mt_btp_init(b, rx, 0);
    if (r.len < HS_RESP_LEN || r.p[0] != HS_FLAGS || r.p[1] != HS_OPCODE || (r.p[2] & 0xF) != HS_VERSION)
        return fail(b, MT_ERR_INVALID);
    frag = mt_get_le16(r.p + 3);
    if (frag < MT_BTP_MIN_FRAG || frag > MT_BTP_MAX_FRAG || r.p[5] == 0)
        return fail(b, MT_ERR_INVALID);
    b->frag = (uint8_t)frag;
    b->window = r.p[5];
    b->state = S_OPEN;
    b->rx_next = 1;              /* the response was the peripheral's 0 ... */
    b->rx_last = 0;
    b->rx_pend = 1;              /* ... and our first packet acks it (at once: not a keep-alive) */
    b->rx_data = true;
    b->ack_due = true;
    b->ack_since = now_ms;
    return MT_OK;
}
