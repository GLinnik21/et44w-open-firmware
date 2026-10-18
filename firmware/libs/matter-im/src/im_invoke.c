/* InvokeRequest with MaxPathsPerInvoke = 1. The response command's id is only known after the
 * handler ran, so its fields are written further up the TX buffer and moved down behind the path. */
#include <string.h>
#include "im_priv.h"

mt_err mt_im_field(const mt_tlv_rd *fields, uint8_t tag, mt_tlv_rd *out)
{
    *out = *fields;
    if (out->type != MT_TLV_STRUCT || mt_tlv_enter(out)) return MT_ERR_INVALID;
    return mt_tlv_find_ctx(out, tag);
}

#define PATH_ROOM 24   /* CommandDataIB start + CommandPathIB with 16/32/32-bit ids: <= 21 bytes */
#define RESP_TRAILER 11 /* CommandRef, end of CommandDataIB, IB, array, IM revision, message end */

static mt_err put_cmd_path(mt_tlv_wr *w, const mt_im_cmd *c, uint32_t cmd)
{
    mt_err e = mt_tlv_start(w, CTX(0), MT_TLV_LIST);
    if (!e) e = mt_tlv_put_u(w, CTX(0), c->endpoint);
    if (!e) e = mt_tlv_put_u(w, CTX(1), c->cluster);
    if (!e) e = mt_tlv_put_u(w, CTX(2), cmd);
    return e ? e : mt_tlv_end(w);
}

/* CommandDataIB (reader on it): path, fields (type NONE if absent), optional CommandRef. */
static mt_err parse_cmd(mt_tlv_rd *ib, mt_im_cmd *c, mt_tlv_rd *fields, bool *has_ref, uint16_t *ref)
{
    mt_tlv_rd r = *ib;
    bool has_path = false;
    mt_err e = mt_tlv_enter(&r);
    c->endpoint = MT_IM_WILD_EP;
    c->cluster = c->command = MT_IM_WILD_ID;
    while (!e && !(e = mt_tlv_next(&r))) {
        if (mt_tlv_is_ctx(&r, 0)) {
            mt_tlv_rd p = r;
            has_path = true;
            e = mt_tlv_enter(&p);
            while (!e && !(e = mt_tlv_next(&p))) {
                if (mt_tlv_is_ctx(&p, 0)) e = mt_tlv_get_u16(&p, &c->endpoint);
                else if (mt_tlv_is_ctx(&p, 1)) e = mt_tlv_get_u32(&p, &c->cluster);
                else if (mt_tlv_is_ctx(&p, 2)) e = mt_tlv_get_u32(&p, &c->command);
            }
            if (e == MT_ERR_NOT_FOUND) e = MT_OK;
        } else if (mt_tlv_is_ctx(&r, 1)) {
            *fields = r;
        } else if (mt_tlv_is_ctx(&r, 2)) {
            *has_ref = !(e = mt_tlv_get_u16(&r, ref));
        }
    }
    return e == MT_ERR_NOT_FOUND && has_path ? MT_OK : MT_ERR_INVALID;
}

static mt_im_status check(mt_im *im, const mt_im_subject *s, const mt_im_cmd *c, bool timed)
{
    mt_im_attr a;
    uint8_t priv;
    bool need_timed;
    mt_im_status st = im_lookup(im, c->endpoint, c->cluster, MT_IM_WILD_ID, NULL, &a);
    if (st) return st;
    if (im->dm->cmd_info(im->dm_ctx, c, &priv, &need_timed)) return MT_IM_UNSUPPORTED_COMMAND;
    if (!im->dm->access(im->dm_ctx, s, c->endpoint, c->cluster, priv)) return MT_IM_UNSUPPORTED_ACCESS;
    if (need_timed && !timed) return MT_IM_NEEDS_TIMED_INTERACTION;
    return MT_IM_SUCCESS;
}

/* ---- deferred answers ---- */

bool im_defer_drop(mt_im *im, uint16_t exch)
{
    bool hit = false;
    for (unsigned i = 0; i < MT_IM_N_DEFER; i++)
        if (im->defer[i].used && im->defer[i].exch == exch) {
            im->defer[i].used = false;
            hit = true;
        }
    return hit;
}

void im_defer_drop_session(mt_im *im, uint16_t session)
{
    for (unsigned i = 0; i < MT_IM_N_DEFER; i++)
        if (im->defer[i].used && im->defer[i].session == session) im->defer[i].used = false;
}

/* The handler returned MT_IM_DEFER: remember the invoke and keep the exchange. SUCCESS = the answer is deferred. */
static mt_im_status defer_take(mt_im *im, uint16_t session, uint16_t exch, const mt_im_cmd *c, bool has_ref,
                               uint16_t ref)
{
    mt_im_defer *d = NULL;
    if (!im->port->hold) return MT_IM_FAILURE;
    for (unsigned i = 0; i < MT_IM_N_DEFER && !d; i++)
        if (!im->defer[i].used) d = &im->defer[i];
    if (!d) return MT_IM_BUSY;
    d->used = true;
    d->exch = exch;
    d->session = session;
    d->cmd = *c;
    d->has_ref = has_ref;
    d->ref = ref;
    im->port->hold(im->port_ctx, exch);
    return MT_IM_SUCCESS;
}

mt_err mt_im_invoke_done(mt_im *im, uint16_t session, uint16_t exch, mt_im_status st, uint32_t resp_cmd,
                         mt_span fields)
{
    mt_im_defer *d = NULL;
    mt_im_defer def;
    mt_tlv_wr w;
    mt_err e;
    for (unsigned i = 0; i < MT_IM_N_DEFER && !d; i++)
        if (im->defer[i].used && im->defer[i].exch == exch && im->defer[i].session == session) d = &im->defer[i];
    if (!d) return MT_ERR_NOT_FOUND;
    def = *d;
    d->used = false;
    mt_tlv_wr_init(&w, im->tx);
    e = mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_bool(&w, CTX(0), false);
    if (!e) e = mt_tlv_start(&w, CTX(1), MT_TLV_ARRAY);
    if (!e) e = mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    if (!e && !st && resp_cmd != MT_IM_WILD_ID) {
        e = mt_tlv_start(&w, CTX(0), MT_TLV_STRUCT);
        if (!e) e = put_cmd_path(&w, &def.cmd, resp_cmd);
        if (!e) e = mt_tlv_start(&w, CTX(1), MT_TLV_STRUCT);
        if (!e && fields.len) e = mt_tlv_put_raw(&w, fields);
        if (!e) e = mt_tlv_end(&w);
    } else if (!e) {
        e = mt_tlv_start(&w, CTX(1), MT_TLV_STRUCT);
        if (!e) e = put_cmd_path(&w, &def.cmd, def.cmd.command);
        if (!e) e = im_put_status_ib(&w, CTX(1), st);
    }
    if (!e && def.has_ref) e = mt_tlv_put_u(&w, CTX(2), def.ref);
    for (int i = 0; i < 3 && !e; i++) e = mt_tlv_end(&w); /* CommandDataIB/StatusIB, InvokeResponseIB, array */
    if (!e) e = im_put_rev_end(&w);
    if (e) { /* does not fit: the requester gets a failure instead */
        im_send_status(im, session, exch, MT_IM_RESOURCE_EXHAUSTED, false);
        return e;
    }
    return im_send(im, session, &exch, MT_IM_OP_INVOKE_RESP, mt_tlv_wr_span(&w), false);
}

void im_on_invoke(mt_im *im, const mt_im_subject *s, uint16_t exch, mt_span payload)
{
    int timed = im_take_timed(im, exch);
    mt_tlv_rd r, list, fields;
    mt_tlv_wr w, fw;
    mt_im_cmd c;
    bool flag = false, suppress = false, has_ref = false;
    uint16_t ref = 0;
    uint32_t resp_cmd = MT_IM_WILD_ID;
    mt_err e = MT_OK;
    mt_im_status st = MT_IM_SUCCESS;
    mt_tlv_rd_init(&list, mt_span_of(NULL, 0));
    mt_tlv_rd_init(&fields, mt_span_of(NULL, 0));
    mt_tlv_rd_init(&r, payload);
    if (mt_tlv_next(&r) || r.type != MT_TLV_STRUCT || mt_tlv_enter(&r)) st = MT_IM_INVALID_ACTION;
    while (!st && !mt_tlv_next(&r)) {
        if (mt_tlv_is_ctx(&r, 0) && mt_tlv_get_bool(&r, &suppress)) st = MT_IM_INVALID_ACTION;
        if (mt_tlv_is_ctx(&r, 1) && mt_tlv_get_bool(&r, &flag)) st = MT_IM_INVALID_ACTION;
        if (mt_tlv_is_ctx(&r, 2)) list = r;
    }
    /* Exactly one CommandDataIB (MaxPathsPerInvoke = 1), concrete path. */
    if (!st && (list.type != MT_TLV_ARRAY || mt_tlv_enter(&list) || mt_tlv_next(&list) ||
                parse_cmd(&list, &c, &fields, &has_ref, &ref) || mt_tlv_next(&list) != MT_ERR_NOT_FOUND ||
                c.endpoint == MT_IM_WILD_EP || c.cluster == MT_IM_WILD_ID || c.command == MT_IM_WILD_ID))
        st = MT_IM_INVALID_ACTION;
    if (!st && timed < 0) st = MT_IM_UNSUPPORTED_ACCESS;
    if (!st && flag != (timed > 0)) st = MT_IM_TIMED_REQUEST_MISMATCH;
    if (st) {
        im_send_status(im, s->session, exch, st, false);
        return;
    }

    mt_tlv_wr_init(&w, im->tx);
    e = mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_bool(&w, CTX(0), false);
    if (!e) e = mt_tlv_start(&w, CTX(1), MT_TLV_ARRAY);
    if (!e) e = mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    if (!e && w.len + PATH_ROOM + RESP_TRAILER + 4 > w.buf.cap) e = MT_ERR_BUFFER_TOO_SMALL;
    if (e) {
        im_send_status(im, s->session, exch, MT_IM_RESOURCE_EXHAUSTED, false);
        return;
    }
    st = check(im, s, &c, timed > 0);
    if (!st) {
        mt_tlv_wr_init(&fw, mt_buf_of(w.buf.p + w.len + PATH_ROOM, w.buf.cap - w.len - PATH_ROOM));
        fw.reserve = RESP_TRAILER;
        st = mt_tlv_start(&fw, CTX(1), MT_TLV_STRUCT) ? MT_IM_RESOURCE_EXHAUSTED
           : (im->cur_exch = exch, im->dm->invoke(im->dm_ctx, s, &c, &fields, &fw, &resp_cmd));
        if (st == MT_IM_DEFER) {
            st = defer_take(im, s->session, exch, &c, has_ref, ref);
            if (!st) return; /* the exchange stays open; mt_im_invoke_done answers */
        }
        /* mt_tlv_end ignores the reserve: a response that ate the trailer room is not sendable */
        if (!st && resp_cmd != MT_IM_WILD_ID && fw.buf.cap - fw.len < RESP_TRAILER) st = MT_IM_RESOURCE_EXHAUSTED;
    }
    if (!st && resp_cmd != MT_IM_WILD_ID) {
        fw.reserve = 0;
        e = mt_tlv_end(&fw);
        if (!e) e = mt_tlv_start(&w, CTX(0), MT_TLV_STRUCT);
        if (!e) e = put_cmd_path(&w, &c, resp_cmd);
        if (!e) {
            memmove(w.buf.p + w.len, fw.buf.p, fw.len);
            w.len += fw.len;
        }
    } else {
        e = mt_tlv_start(&w, CTX(1), MT_TLV_STRUCT);
        if (!e) e = put_cmd_path(&w, &c, c.command);
        if (!e) e = im_put_status_ib(&w, CTX(1), st);
    }
    if (!e && has_ref) e = mt_tlv_put_u(&w, CTX(2), ref);
    for (int i = 0; i < 3 && !e; i++) e = mt_tlv_end(&w); /* CommandDataIB/StatusIB, InvokeResponseIB, array */
    if (!e) e = im_put_rev_end(&w);
    if (e) im_send_status(im, s->session, exch, MT_IM_FAILURE, false);
    else if (!suppress) im_send(im, s->session, &exch, MT_IM_OP_INVOKE_RESP, mt_tlv_wr_span(&w), false);
}
