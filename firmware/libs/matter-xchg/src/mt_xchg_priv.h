/* Internal helpers shared by the matter-xchg sources. Not part of the API. */
#ifndef MT_XCHG_PRIV_H
#define MT_XCHG_PRIV_H

#include <string.h>

#include "mt_xchg.h"

static inline uint32_t xc_now(mt_xchg *m) { return m->p.now_ms(m->p.ctx); }
static inline bool xc_secure(const mt_xchg_session *s) { return s->kind == MT_SESS_PASE || s->kind == MT_SESS_CASE; }
static inline bool xc_mrp(const mt_xchg_session *s) { return s->transport == MT_XCHG_UDP; }
/* Our last reliable message is waiting for its ack (and holds a frame buffer). */
static inline bool xc_awaiting(const mt_xchg_xchg *x) { return x->txbuf >= 0; }

uint32_t xc_random32(mt_xchg *m);
const mt_xchg_proto *xc_find_proto(const mt_xchg *m, uint16_t protocol_id);

/* sessions (mt_xchg_sess.c) */
mt_xchg_session *xs_find_secure(mt_xchg *m, uint16_t local_id);
mt_xchg_session *xs_find_unsecured(mt_xchg *m, uint64_t peer_node, uint8_t transport);
mt_xchg_session *xs_new_unsecured(mt_xchg *m, uint64_t peer_node, uint8_t transport, const mt_xchg_addr *from);
bool xs_has_xchg(const mt_xchg *m, const mt_xchg_session *s);

/* exchanges (mt_xchg_xc.c) */
mt_xchg_xchg *xc_find(mt_xchg *m, const mt_xchg_session *s, uint16_t id, bool initiator);
mt_xchg_xchg *xc_alloc(mt_xchg *m, mt_xchg_session *s, uint16_t id, bool initiator, const mt_xchg_proto *p);
bool xc_have_free(const mt_xchg *m);
/* Releases the exchange; why != 0 reports it to the protocol's on_close. */
void xc_free(mt_xchg *m, mt_xchg_xchg *xc, mt_xchg_end why);
void xc_send_ack(mt_xchg *m, mt_xchg_session *s, uint16_t id, bool we_initiated, uint32_t ack_counter);
void xc_on_ack(mt_xchg *m, mt_xchg_xchg *xc, uint32_t ack_counter);

#endif
