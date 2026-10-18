/* Engine entry points: init, message dispatch, exchange failures, the event log. */
#include <string.h>
#include "im_priv.h"

void mt_im_init(mt_im *im, const mt_im_cfg *cfg)
{
    memset(im, 0, sizeof *im);
    im->dm = cfg->dm;
    im->dm_ctx = cfg->dm_ctx;
    im->port = cfg->port;
    im->port_ctx = cfg->port_ctx;
    im->tx = cfg->tx;
    im->next_sub_id = cfg->sub_id_seed;
    im->next_event = cfg->event_base ? cfg->event_base : 1; /* 0 marks an empty log slot */
}

/* Drops whatever waits on exch; true if something did. */
static bool drop_exch(mt_im *im, uint16_t exch)
{
    bool hit = false;
    for (unsigned i = 0; i < MT_IM_N_READS; i++)
        if (im->reads[i].q.state != Q_FREE && im->reads[i].q.exch == exch) {
            im->reads[i].q.state = Q_FREE;
            hit = true;
        }
    for (unsigned i = 0; i < MT_IM_N_SUBS; i++) {
        mt_im_query *q = &im->subs[i].q;
        if ((q->state == Q_WAIT || q->state == Q_REPORT) && q->exch == exch) {
            im_sub_free(im, &im->subs[i]);
            hit = true;
        }
    }
    if (im_defer_drop(im, exch)) hit = true;
    return hit;
}

void mt_im_on_msg(mt_im *im, const mt_im_subject *s, uint16_t exch, uint8_t opcode, mt_span payload)
{
    /* Interactions run on CASE or PASE sessions only; the ACL check alone must not be the only guard. */
    if (s->auth != MT_IM_AUTH_PASE && s->auth != MT_IM_AUTH_CASE) return;
    if (opcode == MT_IM_OP_STATUS) {
        mt_im_status st;
        if (im_parse_status_resp(payload, &st)) st = MT_IM_FAILURE;
        if (!im_read_on_status(im, exch, st) && !im_sub_on_status(im, exch, st)) {
            mt_im_xstate *x = im_xs_find(im, exch);
            if (x) x->kind = X_FREE; /* a client aborting its timed/chunked interaction */
            im_defer_drop(im, exch);
        }
        return;
    }
    mt_im_xstate *x = im_xs_find(im, exch);
    bool bad = drop_exch(im, exch);
    if (x && (x->kind == X_TIMED ? opcode != MT_IM_OP_WRITE && opcode != MT_IM_OP_INVOKE : opcode != MT_IM_OP_WRITE)) {
        x->kind = X_FREE;
        bad = true;
    }
    if (bad) {
        im_send_status(im, s->session, exch, MT_IM_INVALID_ACTION, false);
        return;
    }
    switch (opcode) {
    case MT_IM_OP_READ: im_on_read(im, s, exch, payload); break;
    case MT_IM_OP_SUBSCRIBE: im_on_subscribe(im, s, exch, payload); break;
    case MT_IM_OP_WRITE: im_on_write(im, s, exch, payload); break;
    case MT_IM_OP_INVOKE: im_on_invoke(im, s, exch, payload); break;
    case MT_IM_OP_TIMED: im_on_timed(im, s, exch, payload); break;
    default: im_send_status(im, s->session, exch, MT_IM_INVALID_ACTION, false); break;
    }
}

void mt_im_on_exchange_failed(mt_im *im, uint16_t exch)
{
    mt_im_xstate *x = im_xs_find(im, exch);
    if (x) x->kind = X_FREE;
    drop_exch(im, exch);
}

mt_err mt_im_event_emit(mt_im *im, uint16_t endpoint, uint32_t cluster, uint32_t id, uint8_t priority,
                        mt_span fields, uint64_t *number)
{
    if (fields.len > MT_IM_EVENT_DATA_MAX) return MT_ERR_INVALID;
    mt_im_event *e = &im->events[0];
    for (unsigned i = 1; i < MT_IM_N_EVENTS; i++)
        if (im->events[i].number < e->number) e = &im->events[i];
    e->number = im->next_event++;
    e->endpoint = endpoint;
    e->cluster = cluster;
    e->id = id;
    e->priority = priority;
    e->sys_ms = im_now(im);
    e->len = (uint8_t)fields.len;
    if (fields.len) memcpy(e->data, fields.p, fields.len);
    if (number) *number = e->number;
    im_sub_mark_events(im, e);
    return MT_OK;
}
