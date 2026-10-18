/* CASE message codecs (case_msg.c), shared with the state machine (mt_case.c). */
#ifndef MT_CASE_INTERNAL_H
#define MT_CASE_INTERNAL_H

#include "mt_case.h"

#define CASE_RANDOM_LEN MT_CASE_RANDOM_LEN

/* Sigma1 (spec 4.14.2, sigma-1-struct). Pointers point into the payload. */
typedef struct {
    const uint8_t *random, *dest_id, *eph_pub;  /* 32, 32, 65 bytes */
    uint16_t session_id;
    mt_sc_peer_params peer;
    bool resumption;                            /* resumptionID + initiatorResumeMIC present (ignored) */
} case_sigma1;
mt_err case_parse_sigma1(mt_span in, case_sigma1 *s);

/* Sigma3 (sigma-3-struct): the encrypted3 field, ciphertext || MIC, longer than the MIC. */
mt_err case_parse_sigma3(mt_span in, mt_span *encrypted);

/* TBEData3 (sigma-3-tbedata): NOC 1..400 B, optional ICAC 1..400 B (len 0 = absent), signature 64 B. */
typedef struct { mt_span noc, icac; const uint8_t *sig; } case_tbe3;
mt_err case_parse_tbe3(mt_span in, case_tbe3 *t);

/* TBSData2 / TBSData3 (sigma-2-tbsdata, sigma-3-tbsdata): { 1 NOC, 2 ICAC (omitted when empty),
 * 3 sender's ephemeral public key, 4 receiver's ephemeral public key }. */
mt_err case_build_tbs(mt_span noc, mt_span icac, const uint8_t sender_eph[MT_P256_POINT_LEN],
                      const uint8_t receiver_eph[MT_P256_POINT_LEN], mt_buf out, mt_span *tbs);
/* TBEData2 (sigma-2-tbedata): { 1 NOC, 2 ICAC (omitted when empty), 3 signature, 4 resumptionID }. */
mt_err case_build_tbe2(mt_span noc, mt_span icac, const uint8_t sig[MT_P256_SIG_LEN],
                       const uint8_t resumption_id[MT_CASE_RESUMPTION_ID_LEN], mt_buf out, mt_span *tbe);
/* Sigma2 (sigma-2-struct): { 1 responderRandom, 2 responderSessionId, 3 responderEphPubKey,
 * 4 encrypted2 (TBEData2 ciphertext || MIC), 5 responderSessionParams (omitted when all zero) }. */
mt_err case_build_sigma2(const uint8_t random[CASE_RANDOM_LEN], uint16_t session_id,
                         const uint8_t eph_pub[MT_P256_POINT_LEN], mt_span encrypted2, const mt_sc_params *params,
                         mt_buf out, mt_span *sigma2);

#endif
