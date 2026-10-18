/* matter-im internals shared by the src/ files (and the host test). Not a public API. */
#ifndef IM_PRIV_H
#define IM_PRIV_H

#include "mt_im.h"

#define CTX(n) mt_tlv_ctx(n)
#define ANON mt_tlv_anon()
#define TAG_REV 0xFF

enum { Q_FREE = 0, Q_WAIT, Q_ACTIVE, Q_REPORT }; /* mt_im_query.state; Q_WAIT = priming (sub) or chunk (read) */
enum { X_FREE = 0, X_TIMED, X_WRITE };            /* mt_im_xstate.kind */
enum { ENC_DONE, ENC_PARTIAL, ENC_NOSPACE };      /* im_enc_attr results */
enum { RPT_LAST, RPT_MORE, RPT_ERR };             /* im_build_report results */

/* ---- codec (im_codec.c) ---- */
mt_err im_put_rev_end(mt_tlv_wr *w);  /* IM revision + end of the message struct */
mt_err im_put_status_ib(mt_tlv_wr *w, mt_tlv_tag tag, mt_im_status st);
mt_err im_put_attr_path(mt_tlv_wr *w, mt_tlv_tag tag, const mt_im_attr *a, bool list_item);
/* Parse an AttributePathIB / EventPathIB list (reader on it, not entered). *list_index: 0 absent,
 * 1 null (append), 2 numeric. */
mt_err im_parse_attr_path(mt_tlv_rd *r, mt_im_path *p, uint8_t *list_index);
mt_err im_parse_event_path(mt_tlv_rd *r, mt_im_path *p);
bool im_path_is_wild(const mt_im_path *p);
/* Does attribute `a` belong to `p`; wildcard flags apply only to wildcard paths. */
bool im_path_match(const mt_im_path *p, const mt_im_attr *a);
/* Status for a concrete (endpoint, cluster, attr) that is not in the enumeration; attr may be
 * MT_IM_WILD_ID to check only the endpoint and cluster. SUCCESS (with idx and out filled) if it exists. */
mt_im_status im_lookup(mt_im *im, uint16_t ep, uint32_t cl, uint32_t attr, uint16_t *idx, mt_im_attr *out);
/* StatusResponse on `exch` (no reply expected). */
void im_send_status(mt_im *im, uint16_t session, uint16_t exch, mt_im_status st, bool expect_resp);
mt_err im_send(mt_im *im, uint16_t session, uint16_t *exch, uint8_t op, mt_span p, bool expect_resp);
static inline uint32_t im_now(mt_im *im) { return im->port->now_ms(im->port_ctx); }

/* ---- reports (im_report.c) ---- */
/* Encode one AttributeReportIB for `a` into an open AttributeReportIBs array, resuming list chunking
 * from *item / *list_mode. allow_partial: the chunk is empty, so a list that does not fit may be cut. */
int im_enc_attr(const mt_im_dm *dm, void *dm_ctx, mt_tlv_wr *w, const mt_im_rctx *rc,
                const mt_im_attr *a, uint16_t *item, uint8_t *list_mode, bool allow_partial);
/* Fill im->tx with the next ReportData chunk for q. sub != NULL: subscription report (sub id; dirty
 * filter unless sub->full or priming). */
int im_build_report(mt_im *im, mt_im_query *q, const mt_im_path *paths, mt_im_sub *sub, mt_span *out);
void im_cursor_reset(mt_im_query *q);

/* ---- read / subscribe (im_read.c, im_sub.c) ---- */
void im_on_read(mt_im *im, const mt_im_subject *s, uint16_t exch, mt_span payload);
void im_on_subscribe(mt_im *im, const mt_im_subject *s, uint16_t exch, mt_span payload);
/* Parse the query part of a Read/SubscribeRequest. tags: attr, event, event filter, fabric filtered,
 * data version filters. */
mt_im_status im_parse_query(mt_im *im, mt_span payload, const uint8_t tags[5], mt_im_query *q,
                            mt_im_path *paths, uint8_t cap);
bool im_read_on_status(mt_im *im, uint16_t exch, mt_im_status st);  /* true if it was a read's */
bool im_sub_on_status(mt_im *im, uint16_t exch, mt_im_status st);
void im_sub_free(mt_im *im, mt_im_sub *s);
bool im_sub_attr_dirty(const mt_im *im, const mt_im_sub *s, const mt_im_attr *a);
void im_sub_mark_events(mt_im *im, const mt_im_event *e);
bool im_event_match(const mt_im_path *p, const mt_im_event *e);

/* ---- write / invoke / timed (im_write.c, im_invoke.c) ---- */
mt_im_xstate *im_xs_find(mt_im *im, uint16_t exch);
/* Consume a pending timed window on exch for a Write/Invoke: 0 none, 1 valid, -1 expired. */
int im_take_timed(mt_im *im, uint16_t exch);
void im_on_timed(mt_im *im, const mt_im_subject *s, uint16_t exch, mt_span payload);
void im_on_write(mt_im *im, const mt_im_subject *s, uint16_t exch, mt_span payload);
void im_on_invoke(mt_im *im, const mt_im_subject *s, uint16_t exch, mt_span payload);
bool im_defer_drop(mt_im *im, uint16_t exch);              /* forget a deferred invoke on exch; true if there was one */
void im_defer_drop_session(mt_im *im, uint16_t session);

/* Read a StatusResponse payload's status. */
mt_err im_parse_status_resp(mt_span payload, mt_im_status *st);

#endif
