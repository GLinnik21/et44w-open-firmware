/* IM codec helpers: paths, StatusIB, StatusResponse, concrete-path lookup. Tag numbers: spec 10.6
 * (cross-checked with rs-matter src/im/encoding). */
#include "im_priv.h"

mt_err im_put_rev_end(mt_tlv_wr *w)
{
    mt_err e = mt_tlv_put_u(w, CTX(TAG_REV), MT_IM_REVISION);
    return e ? e : mt_tlv_end(w);
}

mt_err im_put_status_ib(mt_tlv_wr *w, mt_tlv_tag tag, mt_im_status st)
{
    mt_err e = mt_tlv_start(w, tag, MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_u(w, CTX(0), st > 0xFF ? MT_IM_FAILURE : st);
    if (!e && st > 0xFF) e = mt_tlv_put_u(w, CTX(1), st & 0xFF);
    return e ? e : mt_tlv_end(w);
}

mt_err im_put_attr_path(mt_tlv_wr *w, mt_tlv_tag tag, const mt_im_attr *a, bool list_item)
{
    mt_err e = mt_tlv_start(w, tag, MT_TLV_LIST);
    if (!e) e = mt_tlv_put_u(w, CTX(2), a->endpoint);
    if (!e) e = mt_tlv_put_u(w, CTX(3), a->cluster);
    if (!e) e = mt_tlv_put_u(w, CTX(4), a->attr);
    if (!e && list_item) e = mt_tlv_put_null(w, CTX(5));
    return e ? e : mt_tlv_end(w);
}

static void path_init(mt_im_path *p, uint16_t flags)
{
    p->endpoint = MT_IM_WILD_EP;
    p->cluster = p->id = MT_IM_WILD_ID;
    p->flags = flags;
}

mt_err im_parse_attr_path(mt_tlv_rd *r, mt_im_path *p, uint8_t *list_index)
{
    mt_err e = mt_tlv_enter(r);
    uint32_t wf;
    path_init(p, 0);
    *list_index = 0;
    while (!e && !(e = mt_tlv_next(r))) {
        if (r->tag.kind != MT_TAG_CTX) continue;
        switch (r->tag.num) {
        case 2: e = mt_tlv_get_u16(r, &p->endpoint); break;
        case 3: e = mt_tlv_get_u32(r, &p->cluster); break;
        case 4: e = mt_tlv_get_u32(r, &p->id); break;
        case 5: *list_index = r->type == MT_TLV_NULL ? 1 : 2; break;
        case 6:
            e = mt_tlv_get_u32(r, &wf);
            p->flags = (uint16_t)(wf & 0x1F7);
            break;
        default: break; /* 0 tag compression, 1 node: ignored */
        }
    }
    return e == MT_ERR_NOT_FOUND ? mt_tlv_exit(r) : e;
}

mt_err im_parse_event_path(mt_tlv_rd *r, mt_im_path *p)
{
    mt_err e = mt_tlv_enter(r);
    path_init(p, MT_IM_PATH_EVENT);
    while (!e && !(e = mt_tlv_next(r))) {
        if (r->tag.kind != MT_TAG_CTX) continue;
        if (r->tag.num == 1) e = mt_tlv_get_u16(r, &p->endpoint);
        else if (r->tag.num == 2) e = mt_tlv_get_u32(r, &p->cluster);
        else if (r->tag.num == 3) e = mt_tlv_get_u32(r, &p->id);
        /* 0 node, 4 urgent: ignored */
    }
    return e == MT_ERR_NOT_FOUND ? mt_tlv_exit(r) : e;
}

bool im_path_is_wild(const mt_im_path *p)
{
    return p->endpoint == MT_IM_WILD_EP || p->cluster == MT_IM_WILD_ID || p->id == MT_IM_WILD_ID;
}

bool im_path_match(const mt_im_path *p, const mt_im_attr *a)
{
    if ((p->endpoint != MT_IM_WILD_EP && p->endpoint != a->endpoint) ||
        (p->cluster != MT_IM_WILD_ID && p->cluster != a->cluster) ||
        (p->id != MT_IM_WILD_ID && p->id != a->attr))
        return false;
    uint16_t f = p->flags;
    bool wep = p->endpoint == MT_IM_WILD_EP, wcl = p->cluster == MT_IM_WILD_ID, wat = p->id == MT_IM_WILD_ID;
    uint32_t id = a->attr;
    if (wep && (f & MT_IM_WF_SKIP_ROOT) && a->endpoint == 0) return false;
    if (wcl && (f & MT_IM_WF_SKIP_CUSTOM) && (a->cluster >> 16)) return false;
    if (wcl && (f & MT_IM_WF_SKIP_DIAG) && a->cluster >= 0x33 && a->cluster <= 0x37) return false;
    if (!wat) return true;
    if ((f & MT_IM_WF_SKIP_CUSTOM) && (id >> 16)) return false;
    if ((f & MT_IM_WF_SKIP_GLOBAL) && id >= 0xF000 && id <= 0xFFFE) return false;
    if ((f & MT_IM_WF_SKIP_ATTR_LIST) && id == 0xFFFB) return false;
    if ((f & MT_IM_WF_SKIP_CMD_LISTS) && (id == 0xFFF8 || id == 0xFFF9)) return false;
    if ((f & MT_IM_WF_SKIP_FIXED) && (a->flags & MT_IM_ATTR_FIXED)) return false;
    if ((f & MT_IM_WF_SKIP_OMITTED) && (a->flags & MT_IM_ATTR_OMITTED)) return false;
    return true;
}

mt_im_status im_lookup(mt_im *im, uint16_t ep, uint32_t cl, uint32_t attr, uint16_t *idx, mt_im_attr *out)
{
    mt_im_status st = MT_IM_UNSUPPORTED_ENDPOINT;
    for (uint16_t i = 0; !im->dm->attr_at(im->dm_ctx, i, out); i++) {
        if (out->endpoint != ep) continue;
        if (st == MT_IM_UNSUPPORTED_ENDPOINT) st = MT_IM_UNSUPPORTED_CLUSTER;
        if (out->cluster != cl) continue;
        st = MT_IM_UNSUPPORTED_ATTRIBUTE;
        if (attr != MT_IM_WILD_ID && out->attr != attr) continue;
        if (idx) *idx = i;
        return MT_IM_SUCCESS;
    }
    return st;
}

mt_err im_send(mt_im *im, uint16_t session, uint16_t *exch, uint8_t op, mt_span p, bool expect_resp)
{
    return im->port->send(im->port_ctx, session, exch, op, p, expect_resp);
}

void im_send_status(mt_im *im, uint16_t session, uint16_t exch, mt_im_status st, bool expect_resp)
{
    uint8_t buf[8];
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_put_u(&w, CTX(0), st & 0xFF);
    im_put_rev_end(&w);
    im_send(im, session, &exch, MT_IM_OP_STATUS, mt_tlv_wr_span(&w), expect_resp);
}

mt_err im_parse_status_resp(mt_span payload, mt_im_status *st)
{
    mt_tlv_rd r;
    uint8_t v;
    mt_tlv_rd_init(&r, payload);
    mt_err e = mt_tlv_next(&r);
    if (!e) e = r.type == MT_TLV_STRUCT ? mt_tlv_enter(&r) : MT_ERR_INVALID;
    if (!e) e = mt_tlv_find_ctx(&r, 0);
    if (!e) e = mt_tlv_get_u8(&r, &v);
    if (!e) *st = v;
    return e;
}
