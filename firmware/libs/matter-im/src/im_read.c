/* ReadRequest handling and the query parser shared with SubscribeRequest. A read that fits one
 * ReportData needs no state; a chunked one keeps its paths in a read slot until the last chunk. */
#include <string.h>
#include "im_priv.h"

/* One array of paths (reader on the array). */
static mt_im_status parse_paths(mt_tlv_rd *r, bool event, mt_im_query *q, mt_im_path *paths, uint8_t cap)
{
    mt_err e = mt_tlv_enter(r);
    uint8_t li;
    while (!e && !(e = mt_tlv_next(r))) {
        if (q->n_paths == cap) return MT_IM_PATHS_EXHAUSTED;
        mt_im_path *p = &paths[q->n_paths++];
        e = event ? im_parse_event_path(r, p) : im_parse_attr_path(r, p, &li);
    }
    return e == MT_ERR_NOT_FOUND && !mt_tlv_exit(r) ? MT_IM_SUCCESS : MT_IM_INVALID_ACTION;
}

/* EventFilterIB {0 node, 1 EventMin}: keep the highest EventMin. */
static mt_err parse_event_filters(mt_tlv_rd *r, mt_im_query *q)
{
    mt_err e = mt_tlv_enter(r);
    uint64_t v;
    while (!e && !(e = mt_tlv_next(r))) {
        mt_tlv_rd f = *r;
        e = mt_tlv_enter(&f);
        if (!e && !mt_tlv_find_ctx(&f, 1) && !(e = mt_tlv_get_u64(&f, &v)) && v > q->ev_min) q->ev_min = v;
    }
    return e == MT_ERR_NOT_FOUND ? mt_tlv_exit(r) : e;
}

/* DataVersionFilterIB {0 ClusterPathIB {0 node, 1 endpoint, 2 cluster}, 1 DataVersion}: a cluster whose
 * version still matches is left out of this report. */
static mt_err parse_dv_filters(mt_im *im, mt_tlv_rd *r, mt_im_query *q)
{
    mt_err e = mt_tlv_enter(r);
    while (!e && !(e = mt_tlv_next(r))) {
        mt_tlv_rd f = *r;
        uint16_t ep = MT_IM_WILD_EP;
        uint32_t cl = MT_IM_WILD_ID, ver = 0;
        bool has_ver = false;
        mt_im_attr a;
        e = mt_tlv_enter(&f);
        while (!e && !(e = mt_tlv_next(&f))) {
            if (mt_tlv_is_ctx(&f, 1)) {
                has_ver = !(e = mt_tlv_get_u32(&f, &ver));
            } else if (mt_tlv_is_ctx(&f, 0)) {
                mt_tlv_rd c = f;
                e = mt_tlv_enter(&c);
                while (!e && !(e = mt_tlv_next(&c))) {
                    if (mt_tlv_is_ctx(&c, 1)) e = mt_tlv_get_u16(&c, &ep);
                    else if (mt_tlv_is_ctx(&c, 2)) e = mt_tlv_get_u32(&c, &cl);
                }
                if (e == MT_ERR_NOT_FOUND) e = MT_OK;
            }
        }
        if (e != MT_ERR_NOT_FOUND) break;
        e = MT_OK;
        if (has_ver && !im_lookup(im, ep, cl, MT_IM_WILD_ID, NULL, &a) && a.dataver == ver && a.cluster_idx < 32)
            q->skip_clusters |= 1u << a.cluster_idx;
    }
    return e == MT_ERR_NOT_FOUND ? mt_tlv_exit(r) : e;
}

mt_im_status im_parse_query(mt_im *im, mt_span payload, const uint8_t tags[5], mt_im_query *q,
                            mt_im_path *paths, uint8_t cap)
{
    mt_tlv_rd r;
    mt_err e;
    mt_tlv_rd_init(&r, payload);
    if (mt_tlv_next(&r) || r.type != MT_TLV_STRUCT || mt_tlv_enter(&r)) return MT_IM_INVALID_ACTION;
    while (!(e = mt_tlv_next(&r))) {
        if (r.tag.kind != MT_TAG_CTX) continue;
        uint32_t n = r.tag.num;
        if (n == tags[0] || n == tags[1]) {
            if (r.type != MT_TLV_ARRAY) return MT_IM_INVALID_ACTION;
            mt_im_status st = parse_paths(&r, n == tags[1], q, paths, cap);
            if (st) return st;
        } else if (n == tags[2]) {
            e = parse_event_filters(&r, q);
        } else if (n == tags[3]) {
            e = mt_tlv_get_bool(&r, &q->fabric_filtered);
        } else if (n == tags[4]) {
            e = parse_dv_filters(im, &r, q);
        }
        if (e) return MT_IM_INVALID_ACTION;
    }
    return e == MT_ERR_NOT_FOUND ? MT_IM_SUCCESS : MT_IM_INVALID_ACTION;
}

static mt_im_read *read_slot(mt_im *im, uint16_t exch, uint8_t state)
{
    for (unsigned i = 0; i < MT_IM_N_READS; i++)
        if (im->reads[i].q.state == state && (state == Q_FREE || im->reads[i].q.exch == exch)) return &im->reads[i];
    return NULL;
}

/* Sends the next chunk of rd: a request on the stack (state Q_FREE) moves into a slot when it needs
 * more than one chunk; a slot is released after its last chunk or on failure. */
static void read_send(mt_im *im, mt_im_read *rd, uint16_t exch)
{
    mt_span out;
    uint16_t ses = rd->q.subj.session;
    int r = im_build_report(im, &rd->q, rd->paths, NULL, &out);
    if (r == RPT_ERR) {
        rd->q.state = Q_FREE;
        im_send_status(im, ses, exch, MT_IM_RESOURCE_EXHAUSTED, false);
        return;
    }
    if (r == RPT_MORE && rd->q.state == Q_FREE) {
        mt_im_read *slot = read_slot(im, 0, Q_FREE);
        if (!slot) {
            im_send_status(im, ses, exch, MT_IM_BUSY, false);
            return;
        }
        *slot = *rd;
        slot->q.state = Q_WAIT;
        slot->q.exch = exch;
        rd = slot;
    }
    if (im_send(im, ses, &exch, MT_IM_OP_REPORT, out, r == RPT_MORE) || r == RPT_LAST) rd->q.state = Q_FREE;
}

void im_on_read(mt_im *im, const mt_im_subject *s, uint16_t exch, mt_span payload)
{
    static const uint8_t tags[5] = { 0, 1, 2, 3, 4 };
    mt_im_read rd;
    memset(&rd, 0, sizeof rd);
    rd.q.subj = *s;
    mt_im_status st = im_parse_query(im, payload, tags, &rd.q, rd.paths, MT_IM_READ_PATHS);
    if (!st && !rd.q.n_paths) st = MT_IM_INVALID_ACTION;
    if (st) {
        im_send_status(im, s->session, exch, st == MT_IM_PATHS_EXHAUSTED ? MT_IM_RESOURCE_EXHAUSTED : st, false);
        return;
    }
    im_cursor_reset(&rd.q);
    read_send(im, &rd, exch);
}

bool im_read_on_status(mt_im *im, uint16_t exch, mt_im_status st)
{
    mt_im_read *rd = read_slot(im, exch, Q_WAIT);
    if (!rd) return false;
    if (st) rd->q.state = Q_FREE;
    else read_send(im, rd, exch);
    return true;
}
