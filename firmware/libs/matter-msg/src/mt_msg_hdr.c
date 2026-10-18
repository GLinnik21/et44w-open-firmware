#include "mt_msg.h"

#define VERSION_MASK 0xF0 /* only version 0 exists */

typedef struct { const uint8_t *p; size_t left; } rd;

static const uint8_t *take(rd *r, size_t n)
{
    const uint8_t *p = r->p;
    if (r->left < n) return NULL;
    r->p += n;
    r->left -= n;
    return p;
}

/* Skips a u16-length-prefixed block (message or secured extensions). */
static mt_err skip_block(rd *r)
{
    const uint8_t *l = take(r, 2);
    if (!l) return MT_ERR_INVALID;
    return take(r, mt_get_le16(l)) ? MT_OK : MT_ERR_INVALID;
}

mt_err mt_msg_hdr_decode(mt_span in, mt_msg_hdr *h, size_t *used)
{
    rd r = { in.p, in.len };
    const uint8_t *f = take(&r, 8); /* flags, session id, security flags, counter */
    if (!f) return MT_ERR_INVALID;
    if (f[0] & VERSION_MASK) return MT_ERR_UNSUPPORTED;
    h->has_src = (f[0] & MT_MSG_FLAG_SRC) != 0;
    h->dsiz = f[0] & MT_MSG_DSIZ_MASK;
    h->session_id = mt_get_le16(f + 1);
    h->sec_flags = f[3];
    h->counter = mt_get_le32(f + 4);
    if (h->dsiz == 3 || (h->sec_flags & MT_MSG_SEC_TYPE_MASK) > 1) return MT_ERR_INVALID;
    if (h->sec_flags & MT_MSG_SEC_PRIVACY) return MT_ERR_UNSUPPORTED;
    h->src = h->dst = 0;
    if (h->has_src) {
        const uint8_t *p = take(&r, 8);
        if (!p) return MT_ERR_INVALID;
        h->src = mt_get_le64(p);
    }
    if (h->dsiz == MT_MSG_DSIZ_NODE || h->dsiz == MT_MSG_DSIZ_GROUP) {
        size_t n = h->dsiz == MT_MSG_DSIZ_NODE ? 8 : 2;
        const uint8_t *p = take(&r, n);
        if (!p) return MT_ERR_INVALID;
        h->dst = n == 8 ? mt_get_le64(p) : mt_get_le16(p);
    }
    if (h->sec_flags & MT_MSG_SEC_EXT) {
        mt_err e = skip_block(&r);
        if (e != MT_OK) return e;
    }
    *used = in.len - r.left;
    return MT_OK;
}

mt_err mt_msg_hdr_encode(const mt_msg_hdr *h, mt_buf out, size_t *used)
{
    size_t n = 8 + (h->has_src ? 8 : 0) + (h->dsiz == MT_MSG_DSIZ_NODE ? 8 : h->dsiz == MT_MSG_DSIZ_GROUP ? 2 : 0);
    uint8_t *p = out.p;
    if (h->dsiz > MT_MSG_DSIZ_GROUP || (h->sec_flags & MT_MSG_SEC_TYPE_MASK) > 1) return MT_ERR_INVALID;
    if (h->sec_flags & (MT_MSG_SEC_PRIVACY | MT_MSG_SEC_EXT)) return MT_ERR_UNSUPPORTED;
    if (out.cap < n) return MT_ERR_BUFFER_TOO_SMALL;
    p[0] = (uint8_t)(h->dsiz | (h->has_src ? MT_MSG_FLAG_SRC : 0));
    mt_put_le16(p + 1, h->session_id);
    p[3] = h->sec_flags;
    mt_put_le32(p + 4, h->counter);
    p += 8;
    if (h->has_src) { mt_put_le64(p, h->src); p += 8; }
    if (h->dsiz == MT_MSG_DSIZ_NODE) mt_put_le64(p, h->dst);
    if (h->dsiz == MT_MSG_DSIZ_GROUP) mt_put_le16(p, (uint16_t)h->dst);
    *used = n;
    return MT_OK;
}

#define XCHG_FLAGS_MASK 0x1F

mt_err mt_proto_hdr_decode(mt_span in, mt_proto_hdr *h, size_t *used)
{
    rd r = { in.p, in.len };
    const uint8_t *f = take(&r, 4); /* flags, opcode, exchange id */
    const uint8_t *p;
    if (!f) return MT_ERR_INVALID;
    h->flags = f[0] & XCHG_FLAGS_MASK;
    h->opcode = f[1];
    h->exchange_id = mt_get_le16(f + 2);
    h->vendor_id = 0;
    if (h->flags & MT_XCHG_VENDOR) {
        if (!(p = take(&r, 2))) return MT_ERR_INVALID;
        h->vendor_id = mt_get_le16(p);
    }
    if (!(p = take(&r, 2))) return MT_ERR_INVALID;
    h->protocol_id = mt_get_le16(p);
    h->ack_counter = 0;
    if (h->flags & MT_XCHG_ACK) {
        if (!(p = take(&r, 4))) return MT_ERR_INVALID;
        h->ack_counter = mt_get_le32(p);
    }
    if (h->flags & MT_XCHG_SECEXT) {
        mt_err e = skip_block(&r);
        if (e != MT_OK) return e;
    }
    *used = in.len - r.left;
    return MT_OK;
}

mt_err mt_proto_hdr_encode(const mt_proto_hdr *h, mt_buf out, size_t *used)
{
    uint8_t flags = h->flags & (MT_XCHG_INITIATOR | MT_XCHG_ACK | MT_XCHG_RELIABLE);
    size_t n = 6 + (h->vendor_id ? 2 : 0) + ((flags & MT_XCHG_ACK) ? 4 : 0);
    uint8_t *p = out.p;
    if (h->flags & MT_XCHG_SECEXT) return MT_ERR_UNSUPPORTED;
    if (out.cap < n) return MT_ERR_BUFFER_TOO_SMALL;
    if (h->vendor_id) flags |= MT_XCHG_VENDOR;
    p[0] = flags;
    p[1] = h->opcode;
    mt_put_le16(p + 2, h->exchange_id);
    p += 4;
    if (h->vendor_id) { mt_put_le16(p, h->vendor_id); p += 2; }
    mt_put_le16(p, h->protocol_id);
    p += 2;
    if (flags & MT_XCHG_ACK) mt_put_le32(p, h->ack_counter);
    *used = n;
    return MT_OK;
}
