#include "mt_msg.h"

#define MIC_LEN MT_CCM_TAG_LEN

/* Spec 4.7.2: nonce = security flags || message counter || source node ID, all little-endian. */
static void make_nonce(uint8_t n[MT_CCM_NONCE_LEN], const mt_msg_hdr *h, uint64_t src)
{
    n[0] = h->sec_flags;
    mt_put_le32(n + 1, h->counter);
    mt_put_le64(n + 5, src);
}

mt_err mt_msg_seal(const uint8_t key[MT_CCM_KEY_LEN], uint64_t src_node, const mt_msg_hdr *h,
                   mt_buf frame, size_t hdr_len, size_t plain_len, size_t *frame_len)
{
    uint8_t nonce[MT_CCM_NONCE_LEN];
    size_t out_len;
    mt_err e;
    if (h->sec_flags & MT_MSG_SEC_TYPE_MASK) return MT_ERR_UNSUPPORTED; /* group sessions */
    /* The receiver takes the nonce's source node from the header when it carries one (mt_msg_open), so a
     * header source that differs from src_node would make a frame nobody can open. */
    if (h->has_src && h->src != src_node) return MT_ERR_INVALID;
    if (hdr_len > frame.cap || plain_len > frame.cap - hdr_len || frame.cap - hdr_len - plain_len < MIC_LEN)
        return MT_ERR_BUFFER_TOO_SMALL;
    make_nonce(nonce, h, src_node);
    e = mt_crypto_ccm_encrypt(key, nonce, mt_span_of(frame.p, hdr_len), mt_span_of(frame.p + hdr_len, plain_len),
                              mt_buf_of(frame.p + hdr_len, plain_len + MIC_LEN), &out_len);
    if (e == MT_OK) *frame_len = hdr_len + out_len;
    return e;
}

mt_err mt_msg_open_decoded(const uint8_t key[MT_CCM_KEY_LEN], uint64_t peer_node, uint8_t *frame, size_t len,
                           const mt_msg_hdr *h, size_t hdr_len, size_t *plain_len)
{
    uint8_t nonce[MT_CCM_NONCE_LEN];
    size_t out_len;
    if (h->sec_flags & MT_MSG_SEC_TYPE_MASK) return MT_ERR_UNSUPPORTED;
    if (hdr_len > len || len - hdr_len < MIC_LEN) return MT_ERR_INVALID;
    make_nonce(nonce, h, h->has_src ? h->src : peer_node);
    mt_err e = mt_crypto_ccm_decrypt(key, nonce, mt_span_of(frame, hdr_len), mt_span_of(frame + hdr_len, len - hdr_len),
                                     mt_buf_of(frame + hdr_len, len - hdr_len - MIC_LEN), &out_len);
    if (e == MT_OK) *plain_len = out_len;
    return e;
}

mt_err mt_msg_open(const uint8_t key[MT_CCM_KEY_LEN], uint64_t peer_node, uint8_t *frame, size_t len,
                   mt_msg_hdr *h, size_t *plain_off, size_t *plain_len)
{
    size_t hdr_len;
    mt_err e = mt_msg_hdr_decode(mt_span_of(frame, len), h, &hdr_len);
    if (e == MT_OK) e = mt_msg_open_decoded(key, peer_node, frame, len, h, hdr_len, plain_len);
    if (e == MT_OK) *plain_off = hdr_len;
    return e;
}
