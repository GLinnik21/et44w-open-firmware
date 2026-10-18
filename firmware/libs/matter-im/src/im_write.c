/* TimedRequest and WriteRequest. Timed rules follow chip's TimedHandler (src/app/TimedHandler.cpp):
 * Success then the action on the same exchange; expired -> UNSUPPORTED_ACCESS; any other message ->
 * INVALID_ACTION; TimedRequest flag disagreeing with the exchange -> TIMED_REQUEST_MISMATCH.
 * A chunked write (MoreChunkedMessages) keeps its exchange: the next chunk's list items append. */
#include "im_priv.h"

mt_im_xstate *im_xs_find(mt_im *im, uint16_t exch)
{
    for (unsigned i = 0; i < MT_IM_N_EXCH; i++)
        if (im->xs[i].kind != X_FREE && im->xs[i].exch == exch) return &im->xs[i];
    return NULL;
}

static mt_im_xstate *xs_new(mt_im *im, uint16_t session, uint16_t exch, uint8_t kind)
{
    for (unsigned i = 0; i < MT_IM_N_EXCH; i++) {
        mt_im_xstate *x = &im->xs[i];
        if (x->kind == X_FREE) {
            x->exch = exch;
            x->session = session;
            x->kind = kind;
            return x;
        }
    }
    return NULL;
}

int im_take_timed(mt_im *im, uint16_t exch)
{
    mt_im_xstate *x = im_xs_find(im, exch);
    if (!x || x->kind != X_TIMED) return 0;
    x->kind = X_FREE;
    return (int32_t)(im_now(im) - x->deadline) > 0 ? -1 : 1;
}

void im_on_timed(mt_im *im, const mt_im_subject *s, uint16_t exch, mt_span payload)
{
    mt_tlv_rd r;
    uint16_t ms = 0;
    mt_im_xstate *x = NULL;
    mt_tlv_rd_init(&r, payload);
    mt_im_status st = MT_IM_INVALID_ACTION;
    if (!mt_tlv_next(&r) && !mt_tlv_enter(&r) && !mt_tlv_find_ctx(&r, 0) && !mt_tlv_get_u16(&r, &ms)) {
        x = xs_new(im, s->session, exch, X_TIMED);
        st = x ? MT_IM_SUCCESS : MT_IM_RESOURCE_EXHAUSTED;
    }
    if (x) x->deadline = im_now(im) + ms;
    im_send_status(im, s->session, exch, st, x != NULL);
}

/* Write access to `a`, or a check already granted for the same path and privilege earlier in this write
 * interaction (chip v1.3 WriteSingleClusterData: ACLCheckCacheHit / CacheACLCheckResult). */
static bool write_allowed(mt_im *im, const mt_im_wctx *wc, const mt_im_attr *a, mt_im_acl_hit *hit)
{
    if (hit->valid && hit->endpoint == a->endpoint && hit->cluster == a->cluster && hit->attr == a->attr &&
        hit->priv == a->write_priv)
        return true;
    if (!im->dm->access(im->dm_ctx, wc->subj, a->endpoint, a->cluster, a->write_priv)) return false;
    hit->valid = true;
    hit->priv = a->write_priv;
    hit->endpoint = a->endpoint;
    hit->cluster = a->cluster;
    hit->attr = a->attr;
    return true;
}

/* Write one concrete attribute; `d` is positioned on the data element. */
static mt_im_status write_one(mt_im *im, const mt_im_wctx *wc, mt_im_acl_hit *hit, const mt_im_attr *a,
                              uint8_t li, bool has_ver, uint32_t ver, mt_tlv_rd *d)
{
    if (!(a->flags & MT_IM_ATTR_WRITABLE)) return MT_IM_UNSUPPORTED_WRITE;
    if (!write_allowed(im, wc, a, hit)) return MT_IM_UNSUPPORTED_ACCESS;
    if ((a->flags & MT_IM_ATTR_TIMED_WRITE) && !wc->timed) return MT_IM_NEEDS_TIMED_INTERACTION;
    if (has_ver && ver != a->dataver) return MT_IM_DATA_VERSION_MISMATCH;
    if (li == 2 || (li == 1 && !(a->flags & MT_IM_ATTR_LIST))) return MT_IM_INVALID_ACTION;
    if (d->type == MT_TLV_NONE) return MT_IM_INVALID_ACTION;
    return im->dm->write(im->dm_ctx, wc, a, li ? MT_IM_WR_LIST_APPEND : MT_IM_WR_VALUE, d);
}

static mt_err put_attr_status(mt_tlv_wr *w, const mt_im_attr *a, mt_im_status st)
{
    mt_err e = mt_tlv_start(w, ANON, MT_TLV_STRUCT);
    if (!e) e = im_put_attr_path(w, CTX(0), a, false);
    if (!e) e = im_put_status_ib(w, CTX(1), st);
    if (!e) e = mt_tlv_end(w);
    /* closing may have used the reserve kept for the message trailer */
    return e || w->buf.cap - w->len >= w->reserve ? e : MT_ERR_BUFFER_TOO_SMALL;
}

/* Dry runs encode this in place of every status: the longest StatusIB (a cluster-specific status adds a field). */
#define DRY_STATUS ((mt_im_status)0x1FFu)

/* One AttributeDataIB (reader on it): statuses go to w. A dry run applies nothing and checks no access: it encodes a
 * worst-case status for every path the IB can produce (wildcard endpoints included), so its size is an upper bound. */
static mt_err write_ib(mt_im *im, const mt_im_wctx *wc, mt_im_acl_hit *hit, mt_tlv_rd *ib, mt_tlv_wr *w, bool dry)
{
    mt_tlv_rd r = *ib, d;
    mt_im_path p;
    uint8_t li = 0;
    uint32_t ver = 0;
    bool has_ver = false, has_path = false;
    mt_err e = mt_tlv_enter(&r);
    mt_tlv_rd_init(&d, mt_span_of(NULL, 0));
    while (!e && !(e = mt_tlv_next(&r))) {
        if (mt_tlv_is_ctx(&r, 0)) has_ver = !(e = mt_tlv_get_u32(&r, &ver));
        else if (mt_tlv_is_ctx(&r, 1)) has_path = !(e = im_parse_attr_path(&r, &p, &li));
        else if (mt_tlv_is_ctx(&r, 2)) d = r;
    }
    if (e != MT_ERR_NOT_FOUND || !has_path || p.cluster == MT_IM_WILD_ID || p.id == MT_IM_WILD_ID)
        return MT_ERR_INVALID;
    mt_im_attr a = { .endpoint = p.endpoint, .cluster = p.cluster, .attr = p.id };
    if (p.endpoint != MT_IM_WILD_EP) {
        mt_im_attr found;
        /* the lookup enumerates into its out-parameter: on a miss the status names the requested path */
        mt_im_status st = im_lookup(im, p.endpoint, p.cluster, p.id, NULL, &found);
        if (!st) a = found;
        if (dry) st = DRY_STATUS;
        else if (!st) st = write_one(im, wc, hit, &a, li, has_ver, ver, &d);
        return put_attr_status(w, &a, st);
    }
    /* Endpoint wildcard: every endpoint with this attribute; access-denied ones are skipped silently. */
    for (uint16_t i = 0; !im->dm->attr_at(im->dm_ctx, i, &a); i++) {
        if (a.cluster != p.cluster || a.attr != p.id) continue;
        if (dry) {
            if ((e = put_attr_status(w, &a, DRY_STATUS)) != MT_OK) return e;
            continue;
        }
        if (!write_allowed(im, wc, &a, hit)) continue;
        mt_tlv_rd dd = d;
        if ((e = put_attr_status(w, &a, write_one(im, wc, hit, &a, li, has_ver, ver, &dd))) != MT_OK) return e;
    }
    return MT_OK;
}

/* Every AttributeDataIB of `list` (reader on the array). A dry run leaves w as it found it. */
static mt_err write_list(mt_im *im, const mt_im_wctx *wc, mt_im_acl_hit *hit, mt_tlv_rd list, mt_tlv_wr *w, bool dry)
{
    mt_tlv_mark m = mt_tlv_wr_mark(w);
    mt_err e = mt_tlv_enter(&list);
    while (!e && !(e = mt_tlv_next(&list))) e = write_ib(im, wc, hit, &list, w, dry);
    if (dry) mt_tlv_wr_rollback(w, m);
    return e == MT_ERR_NOT_FOUND ? MT_OK : e;
}

void im_on_write(mt_im *im, const mt_im_subject *s, uint16_t exch, mt_span payload)
{
    mt_im_xstate *x = im_xs_find(im, exch);
    /* a chunked write continues only on the session that began it (its cached access grant is that session's) */
    if (x && x->session != s->session) x = NULL;
    bool cont = x && x->kind == X_WRITE, flag = false, more = false;
    int timed = cont ? x->timed : im_take_timed(im, exch);
    mt_tlv_rd r, list;
    mt_tlv_wr w;
    mt_err e = MT_OK;
    mt_im_status st = MT_IM_SUCCESS;
    mt_tlv_rd_init(&list, mt_span_of(NULL, 0));
    mt_tlv_rd_init(&r, payload);
    if (mt_tlv_next(&r) || r.type != MT_TLV_STRUCT || mt_tlv_enter(&r)) st = MT_IM_INVALID_ACTION;
    while (!st && !(e = mt_tlv_next(&r))) {
        if (mt_tlv_is_ctx(&r, 1) && mt_tlv_get_bool(&r, &flag)) st = MT_IM_INVALID_ACTION;
        if (mt_tlv_is_ctx(&r, 3) && mt_tlv_get_bool(&r, &more)) st = MT_IM_INVALID_ACTION;
        if (mt_tlv_is_ctx(&r, 2)) list = r;
    }
    if (!st && list.type != MT_TLV_ARRAY) st = MT_IM_INVALID_ACTION;
    if (!st && timed < 0) st = MT_IM_UNSUPPORTED_ACCESS;
    if (!st && !cont && flag != (timed > 0)) st = MT_IM_TIMED_REQUEST_MISMATCH;
    if (!st && more && !cont && !(x = xs_new(im, s->session, exch, X_WRITE))) st = MT_IM_RESOURCE_EXHAUSTED;
    if (st) {
        if (cont) x->kind = X_FREE;
        im_send_status(im, s->session, exch, st, false);
        return;
    }
    if (more) x->timed = timed > 0;
    mt_im_wctx wc = { s, more, timed > 0 };
    mt_im_acl_hit hit = { 0 };
    if (cont) hit = x->acl;
    mt_tlv_wr_init(&w, im->tx);
    w.reserve = 5; /* end of array, IM revision, end of message */
    e = mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    if (!e) e = mt_tlv_start(&w, CTX(0), MT_TLV_ARRAY);
    /* Dry run first: a request that is malformed or whose statuses could not all fit is refused with nothing
     * applied (a RESOURCE_EXHAUSTED after some writes went through would make the controller retry them). */
    if (!e) e = write_list(im, &wc, &hit, list, &w, true);
    if (!e) e = write_list(im, &wc, &hit, list, &w, false);
    if (more) x->acl = hit;
    w.reserve = 0;
    if (!e) e = mt_tlv_end(&w);
    if (!e) e = im_put_rev_end(&w);
    if (!more && x) x->kind = X_FREE;
    if (e) {
        if (x) x->kind = X_FREE;
        im_send_status(im, s->session, exch, e == MT_ERR_BUFFER_TOO_SMALL ? MT_IM_RESOURCE_EXHAUSTED : MT_IM_INVALID_ACTION, false);
        return;
    }
    if (im_send(im, s->session, &exch, MT_IM_OP_WRITE_RESP, mt_tlv_wr_span(&w), more) && x) x->kind = X_FREE;
}
