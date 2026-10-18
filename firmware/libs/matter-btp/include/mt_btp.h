/* BTP (Matter over BLE) engine for the peripheral/responder side. Pure C11: bytes in, bytes out, the
 * clock is injected. No allocation; the caller owns the reassembly buffer and the message being sent.
 *
 * Port loop: GATT write on C1 -> mt_btp_rx(); then drain mt_btp_poll() and indicate each packet on C2;
 * after mt_btp_send() or when mt_btp_wait_ms() expires, drain mt_btp_poll() again. Any error closes the
 * engine (mt_btp_closed()); the port then drops the BLE connection. MRP is not used over BTP. */
#ifndef MT_BTP_H
#define MT_BTP_H

#include <stdbool.h>
#include "mt_core.h"

#ifndef MT_BTP_MAX_WINDOW
#define MT_BTP_MAX_WINDOW 5      /* our receive window, packets */
#endif
#define MT_BTP_MAX_FRAG   244    /* largest BTP packet (spec cap, ATT MTU 247) */
#define MT_BTP_MIN_FRAG   6      /* header (5) + 1 */
#define MT_BTP_HS_REQ_LEN 9      /* handshake request: flags, opcode, 4 version bytes, ATT MTU, window */
#define MT_BTP_ACK_SEND_MS 2500  /* send a standalone ack after this long (the keep-alive period on an idle link) */
#define MT_BTP_ACK_WAIT_MS 15000 /* close if our packets stay unacked this long */

typedef struct {
    mt_buf rx;                  /* reassembly area, up to 65535 bytes */
    mt_span tx;                 /* message being segmented */
    uint32_t ack_since, wait_start;
    uint16_t rx_len, rx_got, tx_off, fallback_mtu;
    uint8_t state, rx_state, err, frag, window;
    uint8_t tx_next, tx_oldest, tx_newest, rx_next, rx_last, rx_pend;
    bool tx_exp, ack_due, hs_pending;
    bool rx_data;               /* rx_pend includes a data packet (standalone acks alone are acked by the timer) */
} mt_btp;

/* A fresh engine waits for the handshake request. fallback_mtu is used when the central reports ATT MTU 0
 * (pass the port's known MTU, or 0 for the 23-byte default). */
void mt_btp_init(mt_btp *b, mt_buf rx, uint16_t fallback_mtu);

/* One GATT write received on C1. Closes the engine and returns the error on any protocol violation. */
mt_err mt_btp_rx(mt_btp *b, uint32_t now_ms, mt_span pkt);

/* A completed message (valid until mt_btp_msg_release), or an empty span. Release before the peer's
 * next message starts, otherwise that message closes the connection (STATE). */
mt_span mt_btp_msg(const mt_btp *b);
void mt_btp_msg_release(mt_btp *b);

/* Queue one message (borrowed, must stay valid until mt_btp_tx_idle()). One at a time. */
mt_err mt_btp_send(mt_btp *b, mt_span msg);
bool mt_btp_tx_idle(const mt_btp *b);

/* Next packet to indicate on C2 into out (capacity >= mt_btp_frag_size()), or 0 if none. Also runs the
 * ack timers. */
size_t mt_btp_poll(mt_btp *b, uint32_t now_ms, mt_buf out);

/* Milliseconds until poll needs to run again for a timer; 0 = poll now; UINT32_MAX = nothing pending. */
uint32_t mt_btp_wait_ms(const mt_btp *b, uint32_t now_ms);

/* Caps the segment size at this connection's ATT MTU minus 3 (chip BLEEndPoint takes the smaller of the
 * central's reported MTU and the connection's). Call after the handshake request, before the response is polled. */
void mt_btp_limit_mtu(mt_btp *b, uint16_t att_mtu);

bool mt_btp_open(const mt_btp *b);   /* handshake done, not closed */
bool mt_btp_closed(const mt_btp *b);
mt_err mt_btp_error(const mt_btp *b); /* why it closed */
uint16_t mt_btp_frag_size(const mt_btp *b); /* negotiated max packet size */

/* ---- central side, for test peers (host tests drive the node over a fake BLE link; the device never links these) */
/* The handshake request a central writes first: version 4 only, its ATT MTU, its receive window. */
size_t mt_btp_hs_request(uint8_t out[MT_BTP_HS_REQ_LEN], uint16_t mtu, uint8_t window);
/* Opens a central-side engine from the peripheral's handshake response (segment size, window): the request was
 * unnumbered, the response was the peripheral's packet 0 and the central owes its ack; the central's first packet is
 * its 0, the peripheral's next is its 1. MT_ERR_INVALID for a malformed response. Then use the engine as above
 * (mt_btp_rx for indications, mt_btp_poll for writes). */
mt_err mt_btp_central_open(mt_btp *b, mt_buf rx, uint32_t now_ms, mt_span response);

#endif
