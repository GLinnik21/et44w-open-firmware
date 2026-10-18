/* Subscriptions: SubscribeRequest, priming, interval negotiation, dirty-path and liveness reports,
 * eviction and reaping. Every subscription report expects a StatusResponse (SuppressResponse is never
 * set), so a lost or rejected report reaps the subscription.
 *
 * Dirty tracking: one global set of dirty paths stamped with a generation; a subscription reports the
 * entries newer than what it already reported. If the set overflows, every subscription gets a full
 * report instead. */
#include <string.h>
#include "im_priv.h"

static bool covers(const mt_im_path *p, uint16_t ep, uint32_t cl, uint32_t id)
{
    return (p->endpoint == MT_IM_WILD_EP || ep == MT_IM_WILD_EP || p->endpoint == ep) &&
           (p->cluster == MT_IM_WILD_ID || cl == MT_IM_WILD_ID || p->cluster == cl) &&
           (p->id == MT_IM_WILD_ID || id == MT_IM_WILD_ID || p->id == id);
}

static bool sub_covers(const mt_im_sub *s, const mt_im_path *d)
{
    for (unsigned i = 0; i < s->q.n_paths; i++)
        if (!(s->paths[i].flags & MT_IM_PATH_EVENT) && covers(&s->paths[i], d->endpoint, d->cluster, d->id))
            return true;
    return false;
}

bool im_sub_attr_dirty(const mt_im *im, const mt_im_sub *s, const mt_im_attr *a)
{
    for (unsigned i = 0; i < MT_IM_N_DIRTY; i++) {
        const mt_im_dirty *d = &im->dirty[i];
        if (d->gen > s->gen_seen && d->gen <= s->gen_target && covers(&d->path, a->endpoint, a->cluster, a->attr))
            return true;
    }
    return false;
}

/* Anything to report since the last completed report. */
static bool sub_pending(const mt_im *im, const mt_im_sub *s)
{
    if (im->full_gen > s->gen_seen) return true;
    for (unsigned i = 0; i < MT_IM_N_DIRTY; i++)
        if (im->dirty[i].gen > s->gen_seen && sub_covers(s, &im->dirty[i].path)) return true;
    for (unsigned i = 0; i < MT_IM_N_EVENTS; i++) {
        const mt_im_event *e = &im->events[i];
        if (e->number && e->number >= s->q.ev_min)
            for (unsigned j = 0; j < s->q.n_paths; j++)
                if (im_event_match(&s->paths[j], e)) return true;
    }
    return false;
}

void im_sub_free(mt_im *im, mt_im_sub *s)
{
    (void)im;
    memset(s, 0, sizeof *s);
}

unsigned mt_im_sub_count(const mt_im *im)
{
    unsigned n = 0;
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++) n += im->subs[i].q.state != Q_FREE;
    return n;
}

unsigned mt_im_sub_count_session(const mt_im *im, uint16_t session)
{
    unsigned n = 0;
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++) n += im->subs[i].q.state != Q_FREE && im->subs[i].q.subj.session == session;
    return n;
}

static bool same_peer(const mt_im_subject *a, const mt_im_subject *b)
{
    if (a->auth == MT_IM_AUTH_CASE && b->auth == MT_IM_AUTH_CASE)
        return a->fabric == b->fabric && a->node == b->node;
    return a->session == b->session;
}

/* Oldest subscription of `fabric`, preferring one of `peer`. */
static mt_im_sub *oldest(mt_im *im, uint8_t fabric, const mt_im_subject *peer)
{
    mt_im_sub *best = NULL;
    bool best_peer = false;
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++) {
        mt_im_sub *s = &im->subs[i];
        if (s->q.state == Q_FREE || s->q.subj.fabric != fabric) continue;
        bool p = peer && same_peer(&s->q.subj, peer);
        if (!best || (p && !best_peer) ||
            (p == best_peer && (uint32_t)(s->id - im->next_sub_id) < (uint32_t)(best->id - im->next_sub_id))) {
            best = s;
            best_peer = p;
        }
    }
    return best;
}

static unsigned fabric_subs(const mt_im *im, uint8_t fabric)
{
    unsigned n = 0;
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++)
        n += im->subs[i].q.state != Q_FREE && im->subs[i].q.subj.fabric == fabric;
    return n;
}

/* A free slot. When full: a fabric already holding half the slots gives up its oldest (the
 * requester's own first, preferring the same peer), which keeps MT_IM_N_SUBS/2 per fabric for two
 * fabrics. Otherwise none (RESOURCE_EXHAUSTED). */
static mt_im_sub *sub_alloc(mt_im *im, const mt_im_subject *who)
{
    unsigned half = MT_IM_N_SUBS / 2, nbig = 0;
    uint8_t big = 0;
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++) {
        mt_im_sub *s = &im->subs[i];
        if (s->q.state == Q_FREE) return s;
        unsigned n = fabric_subs(im, s->q.subj.fabric);
        if (n > nbig) {
            nbig = n;
            big = s->q.subj.fabric;
        }
    }
    mt_im_sub *v = fabric_subs(im, who->fabric) >= half ? oldest(im, who->fabric, who)
                 : nbig > half ? oldest(im, big, NULL) : NULL;
    if (v) im_sub_free(im, v);
    return v;
}

static void sub_reap(mt_im *im, mt_im_sub *s)
{
    im_sub_free(im, s);
}

/* Builds and sends the next report chunk of s on s->q.exch (MT_IM_NEW_EXCH opens one). */
static void sub_send_chunk(mt_im *im, mt_im_sub *s)
{
    mt_span out;
    int r = im_build_report(im, &s->q, s->paths, s, &out);
    if (r == RPT_ERR || im_send(im, s->q.subj.session, &s->q.exch, MT_IM_OP_REPORT, out, true)) sub_reap(im, s);
}

static void sub_send_response(mt_im *im, mt_im_sub *s)
{
    uint8_t buf[16];
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_put_u(&w, CTX(0), s->id);
    mt_tlv_put_u(&w, CTX(2), s->max_s);
    im_put_rev_end(&w);
    if (im_send(im, s->q.subj.session, &s->q.exch, MT_IM_OP_SUBSCRIBE_RESP, mt_tlv_wr_span(&w), false))
        sub_reap(im, s);
}

/* The report (or priming) in flight has been acknowledged in full. */
static void sub_report_done(mt_im *im, mt_im_sub *s)
{
    s->gen_seen = s->gen_target;
    s->q.ev_min = s->q.cur.ev_next;
    s->q.skip_clusters = 0; /* data-version filters apply to the priming report only */
    s->q.state = Q_ACTIVE;
    s->q.exch = MT_IM_NEW_EXCH;
    s->full = false;
    s->last_ms = im_now(im);
    s->dirty = sub_pending(im, s);
}

void im_on_subscribe(mt_im *im, const mt_im_subject *who, uint16_t exch, mt_span payload)
{
    static const uint8_t tags[5] = { 3, 4, 5, 7, 8 };
    mt_im_sub t;
    mt_tlv_rd r;
    bool keep = false;
    uint16_t floor = 0, ceil = 0;
    memset(&t, 0, sizeof t);
    t.q.subj = *who;
    mt_im_status st = im_parse_query(im, payload, tags, &t.q, t.paths, MT_IM_SUB_PATHS);
    mt_tlv_rd_init(&r, payload);
    if (!st && !mt_tlv_next(&r) && !mt_tlv_enter(&r)) {
        while (!st && !mt_tlv_next(&r)) {
            if (mt_tlv_is_ctx(&r, 0) && mt_tlv_get_bool(&r, &keep)) st = MT_IM_INVALID_ACTION;
            if (mt_tlv_is_ctx(&r, 1) && mt_tlv_get_u16(&r, &floor)) st = MT_IM_INVALID_ACTION;
            if (mt_tlv_is_ctx(&r, 2) && mt_tlv_get_u16(&r, &ceil)) st = MT_IM_INVALID_ACTION;
        }
    }
    if (!st && !t.q.n_paths) st = MT_IM_INVALID_ACTION;
    if (!st && floor > ceil) st = MT_IM_INVALID_ACTION; /* as chip's ReadHandler */
    if (!st && !keep)
        for (unsigned i = 0; i < MT_IM_N_SUBS; i++)
            if (im->subs[i].q.state != Q_FREE && same_peer(&im->subs[i].q.subj, who)) sub_reap(im, &im->subs[i]);
    mt_im_sub *s = st ? NULL : sub_alloc(im, who);
    if (!st && !s) st = MT_IM_RESOURCE_EXHAUSTED;
    if (st) {
        im_send_status(im, who->session, exch, st, false);
        return;
    }
    *s = t;
    s->id = im->next_sub_id++;
    s->min_s = floor;
    /* MaxInterval: the client's ceiling (Apple asks 600 s), capped at 60 min but never below the floor
     * (spec: floor <= MaxInterval <= max(60 min, ceiling)), and at least 1 s so a zero ceiling cannot turn
     * every poll into a liveness report. */
    s->max_s = ceil > MT_IM_MAX_INTERVAL_LIMIT_S ? MT_IM_MAX_INTERVAL_LIMIT_S : ceil;
    if (s->max_s < floor) s->max_s = floor;
    if (s->max_s < MT_IM_MAX_INTERVAL_MIN_S) s->max_s = MT_IM_MAX_INTERVAL_MIN_S;
    s->gen_seen = s->gen_target = im->gen;
    s->q.state = Q_WAIT;
    s->q.exch = exch;
    im_cursor_reset(&s->q);
    sub_send_chunk(im, s);
}

static mt_im_sub *sub_by_exch(mt_im *im, uint16_t exch)
{
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++) {
        mt_im_sub *s = &im->subs[i];
        if ((s->q.state == Q_WAIT || s->q.state == Q_REPORT) && s->q.exch == exch) return s;
    }
    return NULL;
}

bool im_sub_on_status(mt_im *im, uint16_t exch, mt_im_status st)
{
    mt_im_sub *s = sub_by_exch(im, exch);
    if (!s) return false;
    if (st) sub_reap(im, s);
    else if (s->q.cur.phase < 2) sub_send_chunk(im, s);
    else if (s->q.state == Q_WAIT) {
        sub_report_done(im, s);
        s->q.exch = exch;
        sub_send_response(im, s);
        s->q.exch = MT_IM_NEW_EXCH;
    } else {
        sub_report_done(im, s);
    }
    return true;
}

void mt_im_on_session_closed(mt_im *im, uint16_t session)
{
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++)
        if (im->subs[i].q.state != Q_FREE && im->subs[i].q.subj.session == session) sub_reap(im, &im->subs[i]);
    for (unsigned i = 0; i < MT_IM_N_READS; i++)
        if (im->reads[i].q.subj.session == session) im->reads[i].q.state = Q_FREE;
    for (unsigned i = 0; i < MT_IM_N_EXCH; i++)
        if (im->xs[i].session == session) im->xs[i].kind = X_FREE;
    im_defer_drop_session(im, session);
}

void mt_im_on_fabric_removed(mt_im *im, uint8_t fabric)
{
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++)
        if (im->subs[i].q.state != Q_FREE && im->subs[i].q.subj.fabric == fabric) sub_reap(im, &im->subs[i]);
}

uint32_t mt_im_poll(mt_im *im)
{
    uint32_t now = im_now(im), next = UINT32_MAX;
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++) {
        mt_im_sub *s = &im->subs[i];
        if (s->q.state != Q_ACTIVE) continue;
        /* Liveness a little before MaxInterval so MRP delay doesn't trip the client's timeout. */
        uint32_t min_ms = s->min_s * 1000u, live = s->max_s * 875u;
        if (live < min_ms) live = min_ms;
        uint32_t due = s->dirty ? min_ms : live, el = now - s->last_ms;
        if (el < due) {
            if (due - el < next) next = due - el;
            continue;
        }
        s->gen_target = im->gen;
        s->full = im->full_gen > s->gen_seen;
        s->dirty = false;
        s->last_ms = now;
        s->q.state = Q_REPORT;
        s->q.exch = MT_IM_NEW_EXCH;
        im_cursor_reset(&s->q);
        sub_send_chunk(im, s);
    }
    return next;
}

void mt_im_mark_dirty(mt_im *im, uint16_t endpoint, uint32_t cluster, uint32_t attr)
{
    mt_im_path p = { cluster, attr, endpoint, 0 };
    uint32_t gen = ++im->gen, min_seen = gen;
    mt_im_dirty *d = NULL;
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++)
        if (im->subs[i].q.state != Q_FREE && im->subs[i].gen_seen < min_seen) min_seen = im->subs[i].gen_seen;
    for (unsigned i = 0; i < MT_IM_N_DIRTY && !d; i++) { /* already covered: restamp */
        mt_im_path *q = &im->dirty[i].path;
        if (im->dirty[i].gen && (q->endpoint == MT_IM_WILD_EP || q->endpoint == endpoint) &&
            (q->cluster == MT_IM_WILD_ID || q->cluster == cluster) && (q->id == MT_IM_WILD_ID || q->id == attr))
            d = &im->dirty[i];
    }
    for (unsigned i = 0; i < MT_IM_N_DIRTY && !d; i++) /* reported by every subscription: reuse */
        if (im->dirty[i].gen <= min_seen) {
            d = &im->dirty[i];
            d->path = p;
        }
    for (unsigned i = 0; i < MT_IM_N_DIRTY && !d; i++) /* same cluster: widen to all its attributes */
        if (im->dirty[i].path.endpoint == endpoint && im->dirty[i].path.cluster == cluster) {
            d = &im->dirty[i];
            d->path.id = MT_IM_WILD_ID;
        }
    if (d) {
        d->gen = gen;
    } else {
        im->full_gen = gen;
        memset(im->dirty, 0, sizeof im->dirty);
    }
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++) {
        mt_im_sub *s = &im->subs[i];
        if (s->q.state != Q_FREE && (!d || sub_covers(s, &p))) s->dirty = true;
    }
}

void im_sub_mark_events(mt_im *im, const mt_im_event *e)
{
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++) {
        mt_im_sub *s = &im->subs[i];
        for (unsigned j = 0; s->q.state != Q_FREE && j < s->q.n_paths; j++)
            if (im_event_match(&s->paths[j], e)) s->dirty = true;
    }
}
