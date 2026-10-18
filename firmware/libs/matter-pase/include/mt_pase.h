/* Matter PASE (Matter spec 4.14.1), responder / SPAKE2+ verifier side. A pure state machine:
 * payload bytes in, payload bytes out. The caller (xchg / node) owns the transport, the exchange,
 * the 60 s establishment timer and the commissioning window; it feeds each received secure-channel
 * message to mt_pase_recv() and sends back what it returns. Uses the stored verifier (w0, L), so no
 * PBKDF2 runs on the device. Randomness comes from the injected matter-crypto DRBG. */
#ifndef MT_PASE_H
#define MT_PASE_H

#include <stdbool.h>
#include "mt_crypto.h"
#include "mt_sc.h"

/* Secure Channel protocol opcodes used by PASE. */
#define MT_PASE_OP_PARAM_REQ 0x20
#define MT_PASE_OP_PARAM_RESP 0x21
#define MT_PASE_OP_PAKE1 0x22
#define MT_PASE_OP_PAKE2 0x23
#define MT_PASE_OP_PAKE3 0x24
#define MT_PASE_OP_STATUS MT_SC_OP_STATUS

#define MT_PASE_KEY_LEN 16
#define MT_PASE_SALT_MAX 32

/* Older names of the shared Secure Channel types (mt_sc.h), still used by matter-node. */
typedef mt_sc_params mt_pase_params;
typedef mt_sc_peer_params mt_pase_peer_params;

/* Everything the device stores for the passcode. The verifier is (w0, L) from the Matter verifier
 * serialisation (w0 32 B, L 65 B); salt 16..32 B, iterations 1000..100000. */
typedef struct {
    uint8_t w0[MT_P256_SCALAR_LEN];
    uint8_t l[MT_P256_POINT_LEN];
    mt_span salt;
    uint32_t iterations;
    uint16_t session_id;  /* the id we ask the initiator to use when sending to us */
    mt_sc_params params;  /* announced in PBKDFParamResponse (tag 5) */
} mt_pase_config;

typedef enum { MT_PASE_IDLE, MT_PASE_WAIT_PAKE1, MT_PASE_WAIT_PAKE3, MT_PASE_ESTABLISHED, MT_PASE_FAILED } mt_pase_state;

typedef struct {
    const mt_pase_config *cfg;
    mt_rng *rng;
    mt_pase_state state;
    uint16_t peer_session_id;
    mt_sc_peer_params peer;           /* from PBKDFParamRequest tag 5 */
    uint8_t ctx_hash[MT_SHA256_LEN];  /* SHA-256("CHIP PAKE V1 Commissioning" || request || response) */
    uint8_t ke[MT_PASE_KEY_LEN];
    uint8_t ca[MT_SHA256_LEN];        /* the cA we expect in Pake3 */
} mt_pase;

/* cfg and rng must outlive the exchange. */
void mt_pase_init(mt_pase *p, const mt_pase_config *cfg, mt_rng *rng);
/* Wipe all key material and return to IDLE (call when the exchange or session is dropped). */
void mt_pase_reset(mt_pase *p);

/* What to send back: opcode and bytes written to `out`; len 0 = nothing to send. */
typedef struct { uint8_t opcode; size_t len; } mt_pase_reply;

/* Process one received message. MT_OK: reply holds the next message (PBKDFParamResponse, Pake2) or,
 * after a valid Pake3, a success StatusReport and the state is ESTABLISHED.
 * Any other return puts the machine in FAILED. If reply.len > 0 then it is a failure StatusReport
 * (INVALID_PARAMETER) to send before closing the exchange; it is 0 only if `out` cannot even hold the
 * 8-byte report, or when the initiator itself sent a StatusReport (MT_ERR_STATE, no reply). Calls in ESTABLISHED
 * or FAILED return MT_ERR_STATE and change nothing. Errors: MT_ERR_INVALID = malformed message (also an empty or
 * truncated one), MT_ERR_CRYPTO = wrong passcode (bad cA), an invalid point or an RNG failure, MT_ERR_STATE =
 * unexpected opcode, MT_ERR_BUFFER_TOO_SMALL = `out` cannot hold the reply. */
mt_err mt_pase_recv(mt_pase *p, uint8_t opcode, mt_span payload, mt_buf out, mt_pase_reply *reply);

/* Keys for the new secure session; MT_ERR_STATE unless ESTABLISHED. */
typedef struct {
    uint8_t i2r[MT_PASE_KEY_LEN];              /* initiator-to-responder: decrypts what we receive */
    uint8_t r2i[MT_PASE_KEY_LEN];              /* responder-to-initiator: encrypts what we send */
    uint8_t attestation_challenge[MT_PASE_KEY_LEN];
    uint16_t local_session_id, peer_session_id;
    mt_sc_peer_params peer;
} mt_pase_session;
mt_err mt_pase_session_keys(const mt_pase *p, mt_pase_session *out);

/* Older names of mt_sc_status / MT_SC_STATUS_LEN, still used by matter-node. */
#define MT_PASE_STATUS_LEN MT_SC_STATUS_LEN
#define mt_pase_status mt_sc_status

#endif
