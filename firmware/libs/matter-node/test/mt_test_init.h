/* Test initiator ("commissioner" side) for matter-node: a transport-agnostic PASE prover and Interaction
 * Model reader built from matter-msg / matter-tlv / matter-pase primitives. It speaks through two callbacks
 * (send a datagram, receive one with a wait), so the same code drives the in-memory node unit test and the
 * POSIX loopback client of tools/matter-host.
 *
 * It is written from the spec independently of matter-node's handler code, but it shares the frame codecs
 * (matter-msg), SPAKE2+ math (matter-pase) and TLV with the node: tests built on it show self-consistency
 * of this stack, not interoperability with chip-tool or Apple. Test-only code: not part of any firmware. */
#ifndef MT_TEST_INIT_H
#define MT_TEST_INIT_H

#include "mt_crypto.h"
#include "mt_msg.h"
#include "mt_tlv.h"

#define TI_FRAME_MAX 1280
#define TI_MAX_ATTRS 256
#define TI_STR_MAX 24
#define TI_MAX_TRIES 6
#define TI_WAIT_MS 500

typedef struct {
    void *ctx;
    void (*send)(void *ctx, const uint8_t *frame, size_t len);
    /* Copies the next datagram into buf and returns its length; waits up to wait_ms for one and returns 0 if
     * none came (a fake clock may advance by wait_ms instead of sleeping). */
    size_t (*recv)(void *ctx, uint8_t *buf, size_t cap, uint32_t wait_ms);
} ti_io;

typedef struct {                 /* a parsed incoming message; payload points into the receive buffer */
    uint8_t flags, opcode;
    uint16_t xid, protocol;
    uint32_t counter, ack_counter;
    mt_span payload;
    bool secure;
} ti_msg;

typedef struct {
    ti_io io;
    mt_rng rng;
    uint64_t node_id;            /* ephemeral initiator node id (unsecured source) */
    mt_msg_tx unsec_tx, sec_tx;
    mt_msg_rx unsec_rx, sec_rx;
    uint16_t next_xid;
    bool secure;
    uint16_t local_sid, peer_sid;
    uint8_t enc[MT_CCM_KEY_LEN], dec[MT_CCM_KEY_LEN];   /* i2r, r2i */
    uint64_t sec_src, sec_peer;  /* nonce node IDs of the secure session: ours, the node's (0 for PASE, 4.8.1.1) */
    bool ack_owed;               /* a reliable message from the node is not acknowledged yet */
    uint16_t ack_xid;
    uint32_t ack_counter;
    bool force_pake3;            /* test knob: send Pake3 even though cB did not verify, to test the device's check */
    bool ack_secure;             /* the owed ack belongs to a secure message */
    uint8_t rbuf[TI_FRAME_MAX], sbuf[TI_FRAME_MAX], obuf[128];
    unsigned retransmits;        /* requests we had to resend */
    uint16_t status_general, status_code;   /* last StatusReport received (BUSY etc.) */
    uint8_t status_data[8];      /* its ProtocolData after the 8 header bytes */
    size_t status_data_len;
} ti;

void ti_init(ti *t, ti_io io, mt_entropy_fn entropy, void *entropy_ctx);
void ti_free(ti *t);

/* ---- passcode -> w0, w1 (PBKDF2-HMAC-SHA256 over the passcode as 4 LE bytes; the device never runs it) ---- */
mt_err ti_passcode_to_w(mt_rng *rng, uint32_t passcode, mt_span salt, uint32_t iterations, uint8_t w0[32],
                        uint8_t w1[32], uint8_t l[65]);

/* ---- low level ---- */
size_t ti_build(ti *t, bool secure, uint16_t xid, uint8_t flags, uint16_t protocol, uint8_t opcode, mt_span payload,
                uint32_t ack_counter, uint8_t *out, size_t cap);
/* Same, flags exactly as given: without MT_XCHG_INITIATOR it answers on an exchange the node started. */
size_t ti_build_ex(ti *t, bool secure, uint16_t xid, uint8_t flags, uint16_t protocol, uint8_t opcode, mt_span payload,
                   uint32_t ack_counter, uint8_t *out, size_t cap);
mt_err ti_parse(ti *t, uint8_t *frame, size_t len, ti_msg *m);   /* MT_OK only for a fresh, valid message */
/* Reliable request on a new or existing exchange; waits for the response (acks/duplicates are skipped),
 * resending on silence. reply->payload points into t->rbuf. MT_ERR_TIMEOUT when nothing came. */
mt_err ti_transact(ti *t, bool secure, uint16_t xid, uint16_t protocol, uint8_t opcode, mt_span payload,
                   ti_msg *reply);
void ti_send_ack(ti *t);         /* standalone ack for the last reliable message from the node, if owed */
/* Unreliable one-way message (e.g. a failure StatusReport). */
void ti_send_oneway(ti *t, bool secure, uint16_t xid, uint16_t protocol, uint8_t opcode, mt_span payload);

/* ---- PASE ---- */
/* Whole PASE exchange with the salt/iterations the node announces and the given passcode.
 * MT_OK: t->secure is set. MT_ERR_CRYPTO: wrong passcode (cB did not verify; a failure report was sent).
 * With force_pake3 a cB mismatch does not stop the run: Pake3 goes out with the wrong cA and the result is
 * MT_ERR_CRYPTO with status_general/status_code holding the device's failure report.
 * MT_ERR_STATE: the node answered with a StatusReport (see status_general / status_code, e.g. BUSY 8/4).
 * MT_ERR_TIMEOUT: silence. *iterations (optional) receives the PBKDF iteration count the node announced. */
mt_err ti_pase(ti *t, uint32_t passcode, uint32_t *iterations);
/* Only PBKDFParamRequest/Response, leaving the attempt open on the node (to hold the "one attempt" slot). */
mt_err ti_pase_params_only(ti *t);
void ti_close_session(ti *t);    /* CloseSession StatusReport, then drops the keys */

/* ---- Interaction Model read ---- */
typedef struct {
    uint16_t endpoint;
    uint32_t cluster, attr;
    bool is_status, list_item;
    uint16_t status;
    mt_tlv_type type;
    uint64_t val;                /* uint/sint/bool value; element count for an array */
    char str[TI_STR_MAX + 1];    /* utf8 / bytes, truncated */
    size_t str_len;
} ti_attr;

typedef struct {
    ti_attr a[TI_MAX_ATTRS];
    size_t n;
    unsigned chunks;
    bool overflow;
    uint16_t error_status;       /* a StatusResponse instead of a report (0 = none) */
} ti_report;

typedef struct { int32_t endpoint; int64_t cluster, attr; } ti_path;   /* -1 = wildcard */

/* ReadRequest for the paths, reassembling every ReportData chunk (answering MoreChunkedMessages with
 * StatusResponse(SUCCESS) and acking the last). */
mt_err ti_read(ti *t, const ti_path *paths, size_t n_paths, ti_report *out);
const ti_attr *ti_find(const ti_report *r, uint16_t endpoint, uint32_t cluster, uint32_t attr);

/* Raw IM request without a response check, for the "IM on an unsecured session is dropped" test. */
size_t ti_build_read_request(const ti_path *paths, size_t n_paths, uint8_t *out, size_t cap);

#endif
