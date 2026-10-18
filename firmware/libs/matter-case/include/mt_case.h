/* Matter CASE (Matter spec 4.14.2), responder side only. A pure state machine: payload bytes in,
 * payload bytes out. The caller (xchg / node) owns the transport, the exchange, the establishment timer
 * and the session table; it feeds each received secure-channel message to mt_case_recv() and sends back
 * what it returns. Randomness comes from the injected matter-crypto DRBG; fabrics, operational keys and
 * certificates from matter-fabric (committed fabrics and the pending fail-safe fabric alike).
 *
 * Scope: full Sigma1 -> Sigma2 -> Sigma3 only. Resumption fields in Sigma1 are validated and then ignored
 * (always a full Sigma2, never Sigma2_Resume); the resumption ID in TBEData2 is random and never stored.
 *
 * Buffers (no allocation; large data lives in the caller's buffers, but the Sigma3 check keeps three decoded
 * certificates on the stack: mt_case_recv's frame is ~870 B on Cortex-M33 -Os, plus mbedtls ECDSA/ECDH below it):
 *  - `out` (>= MT_CASE_OUT_MIN): the reply payload. It doubles as work space: the TBS/TBE data of Sigma2
 *    are built in it before the Sigma2 itself, and the decrypted TBEData3 is placed in it.
 *  - `work` (>= MT_CASE_WORK): caller scratch for the stored certificates, the TBEData2 ciphertext,
 *    TBSData3 and the certificate-chain check. Free again when mt_case_recv() returns.
 *  `payload`, `out` and `work` must not overlap. */
#ifndef MT_CASE_H
#define MT_CASE_H

#include <stdbool.h>
#include "mt_cert.h"
#include "mt_core.h"
#include "mt_crypto.h"
#include "mt_fabric.h"
#include "mt_sc.h"

/* Secure Channel protocol opcodes used by CASE. */
#define MT_CASE_OP_SIGMA1 0x30
#define MT_CASE_OP_SIGMA2 0x31
#define MT_CASE_OP_SIGMA3 0x32
#define MT_CASE_OP_SIGMA2_RESUME 0x33   /* never sent */
#define MT_CASE_OP_STATUS MT_SC_OP_STATUS

/* Secure Channel protocol codes in a StatusReport. */
#define MT_CASE_CODE_SUCCESS 0           /* SESSION_ESTABLISHMENT_SUCCESS */
#define MT_CASE_CODE_NO_SHARED_ROOT 1    /* NO_SHARED_TRUST_ROOTS */
#define MT_CASE_CODE_INVALID_PARAM 2     /* INVALID_PARAMETER */

#define MT_CASE_KEY_LEN 16
#define MT_CASE_RESUMPTION_ID_LEN 16
#define MT_CASE_CERT_MAX MT_FABRIC_CERT_MAX       /* largest NOC / ICAC we send or accept (400) */
/* Reply / work buffer sizes. The largest Sigma2 (two 400 B certificates, all session parameters) is
 * about 1070 B; the largest accepted TBEData3 is out.cap. */
#define MT_CASE_OUT_MIN 1100
#define MT_CASE_WORK (MT_FABRIC_CERT_MAX + MT_CERT_SCRATCH)

/* Older names of the shared Secure Channel types (mt_sc.h), still used by matter-node. */
typedef mt_sc_params mt_case_params;
typedef mt_sc_peer_params mt_case_peer_params;

typedef struct {
    const mt_fabric_table *fabrics;
    mt_sc_params params;  /* announced in Sigma2 (tag 5) */
} mt_case_config;

typedef enum { MT_CASE_IDLE, MT_CASE_WAIT_SIGMA3, MT_CASE_ESTABLISHED, MT_CASE_FAILED } mt_case_state;

typedef struct {
    const mt_case_config *cfg;
    mt_rng *rng;
    mt_case_state state;
    uint32_t now;                       /* Matter epoch seconds for certificate validity, 0 = unknown */
    uint16_t local_session_id, peer_session_id;
    mt_sc_peer_params peer;
    /* The matched fabric: looked up again by index at Sigma3 and checked to be the same one. */
    uint8_t fabric_index;
    uint64_t fabric_id, node_id;
    uint8_t cfid[MT_CFID_LEN];
    uint8_t ipk[MT_IPK_LEN];
    uint8_t shared[MT_P256_SCALAR_LEN]; /* ECDH shared secret */
    uint8_t eph_pub[MT_P256_POINT_LEN], peer_eph_pub[MT_P256_POINT_LEN];
    mt_sha256 tt;                       /* transcript: Sigma1 || Sigma2 [|| Sigma3] payloads */
    /* Results, valid in ESTABLISHED. */
    uint8_t keys[3 * MT_CASE_KEY_LEN];  /* I2R || R2I || AttestationChallenge */
    uint64_t peer_node_id;
    uint32_t peer_cats[MT_CERT_MAX_CATS];
    uint8_t n_peer_cats;
    /* A StatusReport received from the initiator (state FAILED). */
    uint16_t peer_general, peer_code;
    uint32_t peer_protocol;
} mt_case;

/* cfg and rng must outlive the exchange. local_session_id is the id we ask the initiator to use when
 * sending to us; now is the time for the peer certificates' validity check (Matter epoch s, 0 = skip). */
void mt_case_init(mt_case *c, const mt_case_config *cfg, mt_rng *rng, uint16_t local_session_id, uint32_t now);
/* Wipe all key material and return to IDLE (call when the exchange or session is dropped). */
void mt_case_reset(mt_case *c);

/* What to send back: opcode and bytes written to `out`; len 0 = nothing to send. */
typedef struct { uint8_t opcode; size_t len; } mt_case_reply;

/* Process one received message.
 * MT_OK: reply holds Sigma2 (state WAIT_SIGMA3) or, after a valid Sigma3, a success StatusReport (state
 * ESTABLISHED).
 * Any other return puts the machine in FAILED with a failure StatusReport (general FAILURE, Secure
 * Channel) in reply to send before closing the exchange:
 *  - MT_ERR_NOT_FOUND: no fabric matches the Sigma1 destination ID, or the matched fabric was removed or
 *    replaced before Sigma3 (NO_SHARED_TRUST_ROOTS);
 *  - MT_ERR_INVALID (malformed message, wrong peer fabric or chain), MT_ERR_CRYPTO (bad point, MIC or
 *    signature), MT_ERR_EXPIRED (peer certificate validity), MT_ERR_STATE (unexpected opcode),
 *    MT_ERR_BUFFER_TOO_SMALL, MT_ERR_IO (fabric storage): INVALID_PARAMETER.
 * reply.len is 0 only if `out` cannot even hold the 8-byte report, or when the initiator itself sent a
 * StatusReport: that ends the handshake with MT_ERR_STATE and its codes in peer_general/protocol/code.
 * Calls in ESTABLISHED or FAILED return MT_ERR_STATE and change nothing. */
mt_err mt_case_recv(mt_case *c, uint8_t opcode, mt_span payload, mt_buf out, mt_buf work, mt_case_reply *reply);

/* Keys and identities of the new secure session; MT_ERR_STATE unless ESTABLISHED. */
typedef struct {
    uint8_t i2r[MT_CASE_KEY_LEN];               /* initiator-to-responder: decrypts what we receive */
    uint8_t r2i[MT_CASE_KEY_LEN];               /* responder-to-initiator: encrypts what we send */
    uint8_t attestation_challenge[MT_CASE_KEY_LEN];
    uint16_t local_session_id, peer_session_id;
    uint8_t fabric_index;
    uint64_t local_node_id, peer_node_id;
    uint32_t peer_cats[MT_CERT_MAX_CATS];
    uint8_t n_peer_cats;
    mt_sc_peer_params peer;
} mt_case_session;
mt_err mt_case_session_keys(const mt_case *c, mt_case_session *out);

#endif
