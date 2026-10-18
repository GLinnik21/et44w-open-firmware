/* ReportData builder: attribute reports with chunking at attribute and list-item granularity, events
 * from the log. List chunking follows chip's AttributeValueEncoder (src/app/AttributeValueEncoder.cpp,
 * vectors in src/app/tests/TestAttributeValueEncoder.cpp): the first chunk carries the array with as
 * many items as fit, every later item is its own AttributeDataIB with ListIndex = null. */
#include "im_priv.h"

/* AttributeReportIBs closing + MoreChunked/SuppressResponse + IM revision + message end. */
#define REPORT_TRAILER 7
/* Closing a partial list: array, AttributeDataIB, AttributeReportIB. */
#define LIST_TRAILER 3

static mt_err data_hdr(mt_tlv_wr *w, const mt_im_attr *a, bool list_item)
{
    mt_err e = mt_tlv_start(w, ANON, MT_TLV_STRUCT);
    if (!e) e = mt_tlv_start(w, CTX(1), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_u(w, CTX(0), a->dataver);
    return e ? e : im_put_attr_path(w, CTX(1), a, list_item);
}

static mt_err end2(mt_tlv_wr *w)
{
    mt_err e = mt_tlv_end(w);
    return e ? e : mt_tlv_end(w);
}

/* mt_tlv_end may use reserved bytes, so a finished element is checked against the reserve. */
static mt_err fits(const mt_tlv_wr *w)
{
    return w->buf.cap - w->len >= w->reserve ? MT_OK : MT_ERR_BUFFER_TOO_SMALL;
}

static mt_err enc_list(const mt_im_dm *dm, void *ctx, mt_tlv_wr *w, const mt_im_rctx *rc,
                       const mt_im_attr *a, uint16_t *n)
{
    mt_err e = mt_tlv_start(w, CTX(2), MT_TLV_ARRAY);
    for (*n = 0; !e; ++*n) {
        mt_tlv_mark m = mt_tlv_wr_mark(w);
        e = dm->read(ctx, rc, a, *n, w, ANON);
        if (!e) e = fits(w);
        if (e) mt_tlv_wr_rollback(w, m);
    }
    --*n;
    return e == MT_ERR_NOT_FOUND ? mt_tlv_end(w) : e;
}

static mt_err enc_status(mt_tlv_wr *w, uint16_t ep, uint32_t cl, uint32_t attr, mt_im_status st)
{
    mt_tlv_mark m = mt_tlv_wr_mark(w);
    mt_im_attr a = { .endpoint = ep, .cluster = cl, .attr = attr };
    mt_err e = mt_tlv_start(w, ANON, MT_TLV_STRUCT);
    if (!e) e = mt_tlv_start(w, CTX(0), MT_TLV_STRUCT);
    if (!e) e = im_put_attr_path(w, CTX(0), &a, false);
    if (!e) e = im_put_status_ib(w, CTX(1), st);
    if (!e) e = end2(w);
    if (!e) e = fits(w);
    if (e) mt_tlv_wr_rollback(w, m);
    return e;
}

int im_enc_attr(const mt_im_dm *dm, void *ctx, mt_tlv_wr *w, const mt_im_rctx *rc,
                const mt_im_attr *a, uint16_t *item, uint8_t *list_mode, bool allow_partial)
{
    mt_tlv_mark m = mt_tlv_wr_mark(w);
    bool list = a->flags & MT_IM_ATTR_LIST, any = false;
    uint16_t n;
    mt_err e;
    if (!*list_mode) {
        e = data_hdr(w, a, false);
        if (!e) e = list ? enc_list(dm, ctx, w, rc, a, &n) : dm->read(ctx, rc, a, 0, w, CTX(2));
        if (!e) e = end2(w);
        if (!e) e = fits(w);
        if (!e) return ENC_DONE;
        mt_tlv_wr_rollback(w, m);
        if (e != MT_ERR_BUFFER_TOO_SMALL)
            return enc_status(w, a->endpoint, a->cluster, a->attr, MT_IM_FAILURE) ? ENC_NOSPACE : ENC_DONE;
        if (!list || !allow_partial) return ENC_NOSPACE;
        /* Cut the list: the array with as many items as fit, the rest as list items later. */
        w->reserve += LIST_TRAILER;
        e = data_hdr(w, a, false);
        if (!e) e = enc_list(dm, ctx, w, rc, a, &n);
        w->reserve -= LIST_TRAILER;
        if (e == MT_ERR_BUFFER_TOO_SMALL && w->depth == m.depth + 3) {
            e = mt_tlv_end(w);
            *list_mode = 1;
            *item = n;
        }
        if (!e) e = end2(w);
        if (!e) return *list_mode ? ENC_PARTIAL : ENC_DONE;
        mt_tlv_wr_rollback(w, m);
        *list_mode = 0;
        return ENC_NOSPACE;
    }
    for (;; ++*item) {
        e = data_hdr(w, a, true);
        if (!e) e = dm->read(ctx, rc, a, *item, w, CTX(2));
        if (!e) e = end2(w);
        if (!e) e = fits(w);
        if (!e) {
            any = true;
            m = mt_tlv_wr_mark(w);
            continue;
        }
        mt_tlv_wr_rollback(w, m);
        if (e == MT_ERR_NOT_FOUND) {
            *list_mode = 0;
            *item = 0;
            return ENC_DONE;
        }
        if (e == MT_ERR_BUFFER_TOO_SMALL) return any ? ENC_PARTIAL : ENC_NOSPACE;
        /* A failing item is dropped; the rest of the list continues. */
    }
}

static mt_err enc_event(mt_tlv_wr *w, const mt_im_event *ev)
{
    mt_tlv_mark m = mt_tlv_wr_mark(w);
    mt_err e = mt_tlv_start(w, ANON, MT_TLV_STRUCT);
    if (!e) e = mt_tlv_start(w, CTX(1), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_start(w, CTX(0), MT_TLV_LIST);
    if (!e) e = mt_tlv_put_u(w, CTX(1), ev->endpoint);
    if (!e) e = mt_tlv_put_u(w, CTX(2), ev->cluster);
    if (!e) e = mt_tlv_put_u(w, CTX(3), ev->id);
    if (!e) e = mt_tlv_end(w);
    if (!e) e = mt_tlv_put_u(w, CTX(1), ev->number);
    if (!e) e = mt_tlv_put_u(w, CTX(2), ev->priority);
    if (!e) e = mt_tlv_put_u(w, CTX(4), ev->sys_ms);
    if (!e) e = mt_tlv_start(w, CTX(7), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_raw(w, mt_span_of(ev->data, ev->len));
    if (!e) e = mt_tlv_end(w);
    if (!e) e = end2(w);
    if (!e) e = fits(w);
    if (e) mt_tlv_wr_rollback(w, m);
    return e;
}

bool im_event_match(const mt_im_path *p, const mt_im_event *e)
{
    return (p->flags & MT_IM_PATH_EVENT) && (p->endpoint == MT_IM_WILD_EP || p->endpoint == e->endpoint) &&
           (p->cluster == MT_IM_WILD_ID || p->cluster == e->cluster) && (p->id == MT_IM_WILD_ID || p->id == e->id);
}

void im_cursor_reset(mt_im_query *q)
{
    mt_im_cursor c = { .ev_next = q->ev_min };
    q->cur = c;
}

/* Opens the report array `tag` if needed: false = no room (chunk is full). */
static bool open_array(mt_tlv_wr *w, int *open, int tag)
{
    if (*open == tag) return true;
    if (*open && mt_tlv_end(w)) return false;
    *open = 0;
    if (mt_tlv_start(w, CTX((uint8_t)tag), MT_TLV_ARRAY)) return false;
    *open = tag;
    return true;
}

/* Oldest logged event numbered >= from that `paths` cover, or NULL. */
static const mt_im_event *next_event(const mt_im *im, uint64_t from)
{
    const mt_im_event *best = NULL;
    for (unsigned i = 0; i < MT_IM_N_EVENTS; i++) {
        const mt_im_event *e = &im->events[i];
        if (e->number && e->number >= from && (!best || e->number < best->number)) best = e;
    }
    return best;
}

/* Read access of the last cluster checked: a wildcard walks ~10 attributes per cluster, and the answer only
 * depends on (endpoint, cluster, privilege). Lives for one report_attrs call. */
typedef struct {
    bool valid, ok;
    uint16_t endpoint;
    uint32_t cluster;
    uint8_t priv;
} read_acl;

static bool read_allowed(mt_im *im, const mt_im_query *q, const mt_im_attr *a, read_acl *c)
{
    if (!c->valid || c->endpoint != a->endpoint || c->cluster != a->cluster || c->priv != a->read_priv) {
        c->ok = im->dm->access(im->dm_ctx, &q->subj, a->endpoint, a->cluster, a->read_priv);
        c->valid = true;
        c->endpoint = a->endpoint;
        c->cluster = a->cluster;
        c->priv = a->read_priv;
    }
    return c->ok;
}

/* Attribute phase. Returns false when the chunk is full. */
static bool report_attrs(mt_im *im, mt_im_query *q, const mt_im_path *paths, mt_im_sub *sub,
                         mt_tlv_wr *w, int *open)
{
    mt_im_cursor *c = &q->cur;
    mt_im_rctx rc = { &q->subj, q->fabric_filtered };
    bool dirty_only = sub && q->state != Q_WAIT && !sub->full;
    read_acl acl = { 0 };
    mt_im_attr a;
    for (; c->path < q->n_paths; c->path++, c->attr = 0) {
        const mt_im_path *p = &paths[c->path];
        bool wild = im_path_is_wild(p);
        if (p->flags & MT_IM_PATH_EVENT) continue;
        if (!wild && !c->list_mode) {
            mt_im_status st = im_lookup(im, p->endpoint, p->cluster, p->id, &c->attr, &a);
            if (st == MT_IM_SUCCESS && !im->dm->access(im->dm_ctx, &q->subj, a.endpoint, a.cluster, a.read_priv))
                st = MT_IM_UNSUPPORTED_ACCESS;
            if (st) {
                if (dirty_only) continue;
                if (!open_array(w, open, 1) || enc_status(w, p->endpoint, p->cluster, p->id, st)) return false;
                q->has_report = true;
                continue;
            }
        }
        for (; !im->dm->attr_at(im->dm_ctx, c->attr, &a); c->attr++) {
            if (!im_path_match(p, &a)) continue;
            if (a.cluster_idx < 32 && (q->skip_clusters >> a.cluster_idx & 1)) continue;
            if (dirty_only && !im_sub_attr_dirty(im, sub, &a)) continue;
            if (wild && !read_allowed(im, q, &a, &acl)) continue;
            if (!open_array(w, open, 1)) return false;
            int r = im_enc_attr(im->dm, im->dm_ctx, w, &rc, &a, &c->item, &c->list_mode, !q->has_report);
            if (r == ENC_PARTIAL) {
                q->has_report = true;
                return false;
            }
            if (r == ENC_NOSPACE) {
                if (q->has_report) return false;
                c->list_mode = 0; /* cannot fit even alone: skip it so every chunk makes progress */
                c->item = 0;
            } else {
                q->has_report = true;
            }
            if (!wild) break;
        }
    }
    return true;
}

static bool report_events(mt_im *im, mt_im_query *q, const mt_im_path *paths, mt_tlv_wr *w, int *open)
{
    mt_im_cursor *c = &q->cur;
    const mt_im_event *e;
    while ((e = next_event(im, c->ev_next)) != NULL) {
        bool match = false;
        for (unsigned i = 0; i < q->n_paths && !match; i++) match = im_event_match(&paths[i], e);
        if (match && im->dm->access(im->dm_ctx, &q->subj, e->endpoint, e->cluster, MT_IM_PRIV_VIEW)) {
            if (!open_array(w, open, 2)) return false;
            if (enc_event(w, e)) {
                if (q->has_report) return false;
            } else {
                q->has_report = true;
            }
        }
        c->ev_next = e->number + 1;
    }
    return true;
}

int im_build_report(mt_im *im, mt_im_query *q, const mt_im_path *paths, mt_im_sub *sub, mt_span *out)
{
    mt_tlv_wr w;
    int open = 0;
    bool more = false;
    mt_tlv_wr_init(&w, im->tx);
    q->has_report = false;
    if (mt_tlv_start(&w, ANON, MT_TLV_STRUCT) || (sub && mt_tlv_put_u(&w, CTX(0), sub->id))) return RPT_ERR;
    w.reserve = REPORT_TRAILER;
    if (w.buf.cap < w.len + w.reserve) return RPT_ERR;
    if (q->cur.phase == 0) {
        more = !report_attrs(im, q, paths, sub, &w, &open);
        if (!more) q->cur.phase = 1;
    }
    if (!more && q->cur.phase == 1) {
        more = !report_events(im, q, paths, &w, &open);
        if (!more) q->cur.phase = 2;
    }
    w.reserve = 0;
    mt_err e = open ? mt_tlv_end(&w) : MT_OK;
    if (!e && more) e = mt_tlv_put_bool(&w, CTX(3), true);
    if (!e && !more && !sub) e = mt_tlv_put_bool(&w, CTX(4), true);
    if (!e) e = im_put_rev_end(&w);
    if (e) return RPT_ERR;
    *out = mt_tlv_wr_span(&w);
    return more ? RPT_MORE : RPT_LAST;
}
