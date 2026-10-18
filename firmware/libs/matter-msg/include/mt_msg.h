/* Matter message layer (spec 4.4-4.6): message header, protocol header, secure unicast seal/open and
 * message-counter handling. Pure C11, no allocation. Message extensions are skipped on decode and
 * never produced; the privacy flag and group sessions are rejected as MT_ERR_UNSUPPORTED. */
#ifndef MT_MSG_H
#define MT_MSG_H

#include <stdbool.h>

#include "mt_core.h"
#include "mt_crypto.h"

/* ---- message header ---- */
#define MT_MSG_FLAG_SRC       0x04 /* S: source node ID present */
#define MT_MSG_DSIZ_MASK      0x03
#define MT_MSG_DSIZ_NONE      0
#define MT_MSG_DSIZ_NODE      1    /* 64-bit destination node ID */
#define MT_MSG_DSIZ_GROUP     2    /* 16-bit destination group ID */

#define MT_MSG_SEC_PRIVACY    0x80 /* P: rejected */
#define MT_MSG_SEC_CONTROL    0x40 /* C: secure-channel control message */
#define MT_MSG_SEC_EXT        0x20 /* MX: set by decode when extensions were skipped; rejected by encode */
#define MT_MSG_SEC_TYPE_MASK  0x03 /* 0 unicast, 1 group */

#define MT_MSG_HDR_MAX        24   /* longest header encode produces */

typedef struct {
    uint16_t session_id;   /* 0 = unsecured */
    uint8_t  sec_flags;    /* raw security flags byte (also feeds the nonce) */
    uint32_t counter;
    bool     has_src;
    uint64_t src;
    uint8_t  dsiz;         /* MT_MSG_DSIZ_* */
    uint64_t dst;          /* node ID, or group ID when dsiz == GROUP */
} mt_msg_hdr;

/* Parses a header at the start of in; *used is its encoded length including skipped extensions. */
mt_err mt_msg_hdr_decode(mt_span in, mt_msg_hdr *h, size_t *used);
mt_err mt_msg_hdr_encode(const mt_msg_hdr *h, mt_buf out, size_t *used);

/* ---- protocol header ---- */
#define MT_XCHG_INITIATOR 0x01 /* I */
#define MT_XCHG_ACK       0x02 /* A: ack_counter present */
#define MT_XCHG_RELIABLE  0x04 /* R */
#define MT_XCHG_SECEXT    0x08 /* SX: skipped on decode, rejected by encode */
#define MT_XCHG_VENDOR    0x10 /* V: vendor_id present (derived from vendor_id != 0 on encode) */

#define MT_PROTO_HDR_MAX  12

typedef struct {
    uint8_t  flags;        /* MT_XCHG_* */
    uint8_t  opcode;
    uint16_t exchange_id;
    uint16_t vendor_id;    /* 0 = common (Matter) */
    uint16_t protocol_id;
    uint32_t ack_counter;  /* valid when flags has ACK */
} mt_proto_hdr;

mt_err mt_proto_hdr_decode(mt_span in, mt_proto_hdr *h, size_t *used);
mt_err mt_proto_hdr_encode(const mt_proto_hdr *h, mt_buf out, size_t *used);

/* ---- secure unicast session frames ---- */
/* frame holds the encoded message header at [0, hdr_len) followed by plain_len plaintext bytes (the
 * protocol header and payload). Encrypts the plaintext in place and appends the 16-byte MIC; frame.cap
 * must have room for it. src_node feeds the nonce (spec 4.7.2: the sender's operational node ID, 0 for PASE);
 * a header that carries a source node must carry this one (MT_ERR_INVALID otherwise), since the receiver
 * builds its nonce from the header's source node when present. */
mt_err mt_msg_seal(const uint8_t key[MT_CCM_KEY_LEN], uint64_t src_node, const mt_msg_hdr *h,
                   mt_buf frame, size_t hdr_len, size_t plain_len, size_t *frame_len);

/* Parses the header of frame[0, len) and decrypts the rest in place. The nonce source node is the header's
 * source node when present, else peer_node. On success the plaintext is frame[*plain_off, +*plain_len).
 * MT_ERR_CRYPTO if the MIC does not verify. The caller must run the counter check (mt_msg_rx_accept) only
 * after this succeeds. */
mt_err mt_msg_open(const uint8_t key[MT_CCM_KEY_LEN], uint64_t peer_node, uint8_t *frame, size_t len,
                   mt_msg_hdr *h, size_t *plain_off, size_t *plain_len);
/* The same for a header the caller already decoded (mt_msg_hdr_decode) from frame[0, hdr_len); the
 * plaintext is frame[hdr_len, +*plain_len). */
mt_err mt_msg_open_decoded(const uint8_t key[MT_CCM_KEY_LEN], uint64_t peer_node, uint8_t *frame, size_t len,
                           const mt_msg_hdr *h, size_t hdr_len, size_t *plain_len);

/* ---- message counters (spec 4.6) ---- */
/* Receive window: the highest counter seen plus a 32-bit map of the 32 counters just below it
 * (bit i = max-1-i seen). Counters skipped by a jump larger than the window count as seen. */
typedef struct { uint32_t max; uint32_t seen; bool synced; } mt_msg_rx;

typedef enum {
    MT_MSG_RX_SECURE,    /* encrypted unicast: strictly increasing, no rollover, no resync */
    MT_MSG_RX_UNSECURED  /* modular comparison; a far-behind counter means the peer rebooted and resyncs */
} mt_msg_rx_mode;

void mt_msg_rx_init(mt_msg_rx *rx); /* unsynchronised: the first accepted counter seeds the window */
/* Returns MT_OK and records the counter if it is fresh. MT_ERR_DUPLICATE: the counter was already seen
 * inside the window; the payload must be dropped but, if the exchange asks for it, the message is still
 * acknowledged (the peer's earlier ack may have been lost). MT_ERR_STALE: the counter is older than the
 * 32-message window (secure mode only), so it cannot be judged: drop it silently. The state is untouched
 * in both cases. Call only for authenticated (or unsecured) messages. */
mt_err mt_msg_rx_accept(mt_msg_rx *rx, uint32_t counter, mt_msg_rx_mode mode);

/* Transmit counter. Start at a random 28-bit value (spec 4.6.1.1). The global unencrypted counter is one
 * instance of this, shared by all unsecured sessions, and wraps. A secure counter is exhausted instead of
 * wrapping: next() then fails with MT_ERR_STATE and the session must be closed. */
typedef struct { uint32_t next; bool secure; bool exhausted; } mt_msg_tx;

void mt_msg_tx_init(mt_msg_tx *tx, uint32_t random, bool secure);
mt_err mt_msg_tx_next(mt_msg_tx *tx, uint32_t *counter);

#endif
