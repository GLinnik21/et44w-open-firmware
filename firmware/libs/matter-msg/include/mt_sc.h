/* Secure Channel pieces shared by PASE and CASE (Matter spec 4.11.1, 4.13): the session-parameter-struct
 * and the StatusReport payload. On top of matter-tlv. */
#ifndef MT_SC_H
#define MT_SC_H

#include "mt_core.h"
#include "mt_tlv.h"

#define MT_SC_OP_STATUS 0x40   /* StatusReport opcode */
#define MT_SC_STATUS_LEN 8     /* general code, protocol id (vendor 0, Secure Channel), protocol code */

/* Session parameters we announce (PBKDFParamResponse, Sigma2). A zero field is left out; all zero
 * leaves the whole structure out. Intervals are milliseconds. */
typedef struct {
    uint32_t idle_ms, active_ms, specification_version;
    uint16_t active_threshold_ms, data_model_revision, im_revision, max_paths_per_invoke;
} mt_sc_params;

/* The initiator's MRP parameters (PBKDFParamRequest, Sigma1); 0 = not sent. */
typedef struct { uint32_t idle_ms, active_ms; uint16_t active_threshold_ms; } mt_sc_peer_params;

/* StatusReport payload with protocol Secure Channel, MT_SC_STATUS_LEN bytes. */
mt_err mt_sc_status(uint16_t general, uint16_t protocol_code, mt_buf out, size_t *len);

/* session-parameter-struct under context tag `tag`: 1 idle, 2 active, 3 active threshold, 4 data model
 * revision, 5 IM revision, 6 specification version, 7 max paths per invoke. */
mt_err mt_sc_params_put(mt_tlv_wr *w, uint8_t tag, const mt_sc_params *p);

/* Read the current container element as a session-parameter-struct: enter it, keep the MRP fields
 * (1..3), skip everything else, exit. Callers that require a structure check r->type first. */
mt_err mt_sc_peer_parse(mt_tlv_rd *r, mt_sc_peer_params *o);

#endif
