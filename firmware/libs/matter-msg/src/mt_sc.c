#include "mt_sc.h"

mt_err mt_sc_status(uint16_t general, uint16_t protocol_code, mt_buf out, size_t *len)
{
    if (out.cap < MT_SC_STATUS_LEN) return MT_ERR_BUFFER_TOO_SMALL;
    mt_put_le16(out.p, general);
    mt_put_le32(out.p + 2, 0); /* vendor 0, protocol 0 = Secure Channel */
    mt_put_le16(out.p + 6, protocol_code);
    *len = MT_SC_STATUS_LEN;
    return MT_OK;
}

static mt_err put_u_nz(mt_tlv_wr *w, uint8_t tag, uint32_t v)
{
    return v ? mt_tlv_put_u(w, mt_tlv_ctx(tag), v) : MT_OK;
}

mt_err mt_sc_params_put(mt_tlv_wr *w, uint8_t tag, const mt_sc_params *p)
{
    if (!(p->idle_ms | p->active_ms | p->specification_version | p->active_threshold_ms |
          p->data_model_revision | p->im_revision | p->max_paths_per_invoke))
        return MT_OK;
    mt_err e = mt_tlv_start(w, mt_tlv_ctx(tag), MT_TLV_STRUCT);
    if (!e) e = put_u_nz(w, 1, p->idle_ms);
    if (!e) e = put_u_nz(w, 2, p->active_ms);
    if (!e) e = put_u_nz(w, 3, p->active_threshold_ms);
    if (!e) e = put_u_nz(w, 4, p->data_model_revision);
    if (!e) e = put_u_nz(w, 5, p->im_revision);
    if (!e) e = put_u_nz(w, 6, p->specification_version);
    if (!e) e = put_u_nz(w, 7, p->max_paths_per_invoke);
    return e ? e : mt_tlv_end(w);
}

mt_err mt_sc_peer_parse(mt_tlv_rd *r, mt_sc_peer_params *o)
{
    mt_err e = mt_tlv_enter(r);
    while (!e && !(e = mt_tlv_next(r))) {
        if (mt_tlv_is_ctx(r, 1)) e = mt_tlv_get_u32(r, &o->idle_ms);
        else if (mt_tlv_is_ctx(r, 2)) e = mt_tlv_get_u32(r, &o->active_ms);
        else if (mt_tlv_is_ctx(r, 3)) e = mt_tlv_get_u16(r, &o->active_threshold_ms);
    }
    return e == MT_ERR_NOT_FOUND ? mt_tlv_exit(r) : e;
}
