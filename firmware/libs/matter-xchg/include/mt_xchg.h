/* Matter exchange layer: sessions, exchanges, MRP and dispatch (spec 4.10-4.12). Pure C11, no allocation:
 * the caller owns one mt_xchg and all tables are fixed. Single-threaded: call everything from the Matter task.
 *
 * Time, transmission and randomness come in through mt_xchg_ports. The layer seals and opens secure frames
 * itself (it owns the session keys and counters). Callbacks may call back into this API on the same
 * exchange (send, close) but must not touch an exchange after closing it.
 *
 * Sizing macros may be overridden with -D, but every file that includes this header must agree. */
#ifndef MT_XCHG_H
#define MT_XCHG_H

#include <stdbool.h>

#include "mt_core.h"
#include "mt_msg.h"

#ifndef MT_XCHG_N_SESSIONS
#define MT_XCHG_N_SESSIONS 8
#endif
#ifndef MT_XCHG_N_EXCHANGES
#define MT_XCHG_N_EXCHANGES 6
#endif
#ifndef MT_XCHG_N_PROTOS
#define MT_XCHG_N_PROTOS 4
#endif
/* Frame buffers: one is held per reliable message awaiting its ack; unreliable sends borrow one briefly.
 * Each is MT_XCHG_MAX_FRAME bytes of RAM. */
#ifndef MT_XCHG_N_TXBUF
#define MT_XCHG_N_TXBUF 3
#endif
#ifndef MT_XCHG_MAX_FRAME
/* Largest Matter message (the UDP payload): the 1280-byte IPv6 minimum MTU less 48 bytes of IPv6 + UDP headers
 * (spec 4.4.4; chip v1.3 transport/raw/MessageHeader.h kMaxIPPacketSizeBytes - kMaxUDPAndIPHeaderSizeBytes).
 * matter.js drops larger datagrams. */
#define MT_XCHG_MAX_FRAME 1232
#endif
#define MT_XCHG_MAX_PAYLOAD (MT_XCHG_MAX_FRAME - MT_MSG_HDR_MAX - MT_PROTO_HDR_MAX - MT_CCM_TAG_LEN)

/* ---- MRP parameters (spec 4.12.8, 2.5.x defaults) ---- */
#define MT_XCHG_MAX_RETRANS      4     /* retransmissions after the first send (5 transmissions in all) */
#define MT_XCHG_ACK_TIMEOUT_MS   200   /* MRP_STANDALONE_ACK_TIMEOUT */
#define MT_XCHG_IDLE_DEFAULT_MS  500   /* SESSION_IDLE_INTERVAL when the peer reports none */
#define MT_XCHG_ACTIVE_DEFAULT_MS 300  /* SESSION_ACTIVE_INTERVAL */
#define MT_XCHG_MRP_MAX_MS       3600000u /* the largest idle / active interval a peer may announce (1 hour) */
#define MT_XCHG_ACTIVE_THRESHOLD_MS 4000 /* peer counts as active this long after its last message */
#define MT_XCHG_XCHG_IDLE_MS     60000 /* an exchange nobody touched this long is dropped */
#define MT_XCHG_UNSEC_IDLE_MS    30000 /* an unsecured session without exchanges is reaped after this */

#define MT_XCHG_PROTO_SECURE_CHANNEL 0x0000
#define MT_XCHG_OP_STANDALONE_ACK    0x10

/* ---- transport and peer address ---- */
typedef enum { MT_XCHG_UDP = 0, MT_XCHG_BTP = 1 } mt_xchg_transport; /* MRP runs on UDP only */

/* Opaque to this layer except that it is copied: where to send back. Ignored for BTP. */
typedef struct {
    uint8_t  ip[16];   /* IPv4 as v4-mapped or in ip[0..3]: the port decides */
    uint32_t scope;    /* IPv6 scope / netif index */
    uint16_t port;
    uint8_t  family;   /* port-defined (0 = unset) */
} mt_xchg_addr;

/* ---- ports ---- */
typedef struct {
    void *ctx;
    uint32_t (*now_ms)(void *ctx);   /* free-running, wraps at 2^32 */
    /* Transmit one datagram (UDP) or one message (BTP). Best effort; failures are left to MRP. */
    void (*send)(void *ctx, mt_xchg_transport t, const mt_xchg_addr *to, mt_span frame);
    void (*random)(void *ctx, uint8_t *out, size_t len);
} mt_xchg_ports;

/* ---- sessions ---- */
typedef enum { MT_SESS_FREE = 0, MT_SESS_UNSECURED, MT_SESS_PASE, MT_SESS_CASE } mt_sess_kind;

typedef enum {
    MT_XCHG_END_CLOSED = 1, /* closed by request (CloseSession, RemoveFabric, handshake done) */
    MT_XCHG_END_EVICTED,    /* made room for a new session */
    MT_XCHG_END_MRP,        /* a reliable message was never acknowledged */
    MT_XCHG_END_IDLE,       /* inactivity timeout */
    MT_XCHG_END_TRANSPORT   /* the link under the session went away (BLE disconnect): closed by the owner */
} mt_xchg_end;

typedef struct {
    mt_sess_kind kind;       /* MT_SESS_FREE = slot unused */
    uint8_t  transport;      /* mt_xchg_transport */
    uint8_t  fabric_index;   /* 0 for PASE until AddNOC */
    uint8_t  subs;           /* active subscriptions on this session, set by IM */
    uint16_t local_id;       /* the id peers put in frames to us (0 = unsecured) */
    uint16_t peer_id;        /* the id we put in frames to the peer */
    uint64_t peer_node;      /* unsecured: the initiator's ephemeral node ID; CASE: peer operational node ID */
    uint64_t local_node;     /* nonce source for our frames (0 for PASE) */
    uint32_t idle_ms, active_ms; /* the peer's MRP intervals, at most MT_XCHG_MRP_MAX_MS */
    uint32_t last_activity;  /* last authenticated rx or tx */
    uint32_t last_rx;        /* for the peer-active test */
    mt_xchg_addr addr;
    uint8_t  enc_key[MT_CCM_KEY_LEN]; /* our frames */
    uint8_t  dec_key[MT_CCM_KEY_LEN]; /* peer frames */
    mt_msg_rx rx;
    mt_msg_tx tx;
} mt_xchg_session;

typedef struct {
    mt_sess_kind kind;       /* MT_SESS_PASE or MT_SESS_CASE */
    mt_xchg_transport transport;
    uint8_t  fabric_index;
    uint16_t local_id, peer_id;
    uint64_t peer_node, local_node;
    uint32_t idle_ms, active_ms; /* 0 = defaults */
    const mt_xchg_addr *addr;    /* NULL for BTP */
    uint8_t  enc_key[MT_CCM_KEY_LEN], dec_key[MT_CCM_KEY_LEN];
} mt_xchg_session_params;

/* ---- exchanges and protocol handlers ---- */
typedef struct mt_xchg_xchg mt_xchg_xchg;

typedef struct {
    uint16_t protocol_id;    /* common (vendor 0) protocols only */
    void *ctx;
    /* A message for an exchange (new responder exchange or existing). payload is valid only during the call.
     * Standalone acks and duplicates never get here. */
    void (*on_msg)(void *ctx, mt_xchg_xchg *xc, const mt_proto_hdr *h, mt_span payload);
    /* The exchange was released by the layer: session closed/evicted, MRP gave up, or idle timeout. It is
     * NOT called when the handler itself ended the exchange with mt_xchg_close, except that a deferred close
     * (see mt_xchg_close) later reports MT_XCHG_END_MRP if its last message was never acknowledged. May be NULL. */
    void (*on_close)(void *ctx, mt_xchg_xchg *xc, mt_xchg_end why);
} mt_xchg_proto;

struct mt_xchg_xchg {
    bool     used;
    bool     initiator;      /* we started it */
    bool     closing;        /* close requested; held only until the last reliable message is acked */
    bool     ack_pending;    /* a reliable message was received and not yet acknowledged */
    bool     freeing;        /* being released: its on_close is running (re-entry guard) */
    int8_t   txbuf;          /* >= 0: our last reliable message, held in this pool buffer until acked; else -1 */
    uint8_t  retrans;        /* retransmissions done */
    uint16_t id;
    uint16_t tx_len;
    uint32_t ack_counter;    /* counter to acknowledge (ack_pending) */
    uint32_t tx_counter;     /* counter of the awaiting message */
    uint32_t ack_due, retx_due, last_activity;
    mt_xchg_session *session;
    const mt_xchg_proto *proto;
    void *user;              /* free for the protocol handler */
};

/* Called after a session's exchanges were released and before its slot is freed. IM drops the session's
 * subscriptions here. local_id identifies it (the slot is reused afterwards). */
typedef void (*mt_xchg_session_cb)(void *ctx, const mt_xchg_session *s, mt_xchg_end why);

typedef struct {
    mt_xchg_ports p;
    mt_xchg_session_cb on_session_close;
    void *session_cb_ctx;
    const mt_xchg_proto *protos[MT_XCHG_N_PROTOS];
    mt_xchg_session sess[MT_XCHG_N_SESSIONS];
    mt_xchg_xchg xc[MT_XCHG_N_EXCHANGES];
    uint8_t txbuf[MT_XCHG_N_TXBUF][MT_XCHG_MAX_FRAME];
    bool txbuf_used[MT_XCHG_N_TXBUF];
    mt_msg_tx unsec_tx;      /* the one global unencrypted counter */
    uint16_t next_xchg_id;
    bool commissioning;
    uint32_t rx_no_session;  /* secure frames for a session id we don't hold (e.g. the peer's, from before a reboot) */
    uint32_t rx_bad_mic;     /* secure frames that failed to decrypt */
} mt_xchg;

/* ---- lifecycle ---- */
void mt_xchg_init(mt_xchg *m, const mt_xchg_ports *ports);
mt_err mt_xchg_register(mt_xchg *m, const mt_xchg_proto *p); /* p must outlive m; INVALID on duplicate id */
void mt_xchg_set_session_cb(mt_xchg *m, mt_xchg_session_cb cb, void *ctx);
/* While true a PASE session is never evicted (commissioning window open). */
void mt_xchg_set_commissioning(mt_xchg *m, bool open);

/* ---- sessions ---- */
/* Picks an unused non-zero local session ID. */
mt_err mt_xchg_session_id_alloc(mt_xchg *m, uint16_t *id);
/* Adds an established PASE/CASE session. A full table evicts per the policy below; MT_ERR_BUFFER_TOO_SMALL
 * if nothing may be evicted, MT_ERR_INVALID for a duplicate local_id. */
mt_err mt_xchg_session_add(mt_xchg *m, const mt_xchg_session_params *p, mt_xchg_session **out);
/* Closes the session: its exchanges are released (on_close with why), then the session callback runs. */
void mt_xchg_session_close(mt_xchg *m, mt_xchg_session *s, mt_xchg_end why);
mt_xchg_session *mt_xchg_session_find(mt_xchg *m, uint16_t local_id);
void mt_xchg_session_set_subs(mt_xchg_session *s, uint8_t n);
/* 0 keeps; larger than MT_XCHG_MRP_MAX_MS is clamped to it (the values come from the peer). */
void mt_xchg_session_set_mrp(mt_xchg_session *s, uint32_t idle_ms, uint32_t active_ms);
/* Eviction policy for a full table (lowest class goes first, then not busy, then least recently active):
 *   0 unsecured session without exchanges, 1 PASE with the commissioning window closed,
 *   2 CASE with no exchange and no subscription, 3 CASE with either.
 * Unsecured sessions with exchanges and PASE during the window are never evicted. A new unsecured session
 * (unauthenticated, spoofable) may take class 0-1 only; a new PASE/CASE session takes 0-3. */

/* ---- exchanges ---- */
/* Starts an exchange we initiate (e.g. a subscription report) on a PASE/CASE session. */
mt_err mt_xchg_open(mt_xchg *m, mt_xchg_session *s, uint16_t protocol_id, mt_xchg_xchg **out);
/* Our reliable message counts as acknowledged by its standalone/piggybacked ack, or implicitly by any later
 * non-ack-flagged message from the peer on the same exchange (a lost standalone ack, spec 4.12.7 leaves the
 * peer's next message as proof of receipt; connectedhomeip would instead retransmit until acked).
 * Sends a message on the exchange. reliable asks for MRP (ignored on BTP). A pending ack is piggybacked.
 * MT_ERR_STATE if a reliable message is still unacknowledged or the tx counter is exhausted,
 * MT_ERR_BUFFER_TOO_SMALL if payload is too long or no frame buffer is free (retry later). */
mt_err mt_xchg_send(mt_xchg *m, mt_xchg_xchg *xc, uint8_t opcode, mt_span payload, bool reliable);
/* Ends the exchange. A pending ack goes out at once. If a reliable message is still unacknowledged the slot
 * stays until it is acked or MRP gives up (xc->user must not be used then). */
void mt_xchg_close(mt_xchg *m, mt_xchg_xchg *xc);

/* ---- driving ---- */
/* One received datagram/message. frame is decrypted in place. On an unsecured session (id 0) only the Secure
 * Channel protocol is accepted, and only a peer-initiated, non-ack Secure Channel message opens a new one;
 * everything else there is dropped unacknowledged. */
void mt_xchg_on_rx(mt_xchg *m, mt_xchg_transport t, const mt_xchg_addr *from, uint8_t *frame, size_t len);
/* Runs due timers (retransmit, standalone ack, idle). Returns ms until the next deadline, UINT32_MAX if none. */
uint32_t mt_xchg_poll(mt_xchg *m);

/* MRP backoff (spec 4.12.2.1): base*1.1*1.6^max(0,n-1)*(1+rnd/256*0.25) for n retransmissions done. */
uint32_t mt_xchg_backoff_ms(uint32_t base_ms, unsigned n, uint8_t rnd);

#endif
