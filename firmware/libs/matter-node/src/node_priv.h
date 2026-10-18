/* Internal to matter-node. */
#ifndef MT_NODE_PRIV_H
#define MT_NODE_PRIV_H

#include <string.h>

#include "mt_node.h"

static inline uint32_t node_now(const mt_node *n) { return n->p.now_ms(n->p.ctx); }

mt_node_ex *node_ex_find(mt_node *n, const mt_xchg_xchg *xc);

/* Secure Channel handler (node_sc.c). */
void node_sc_on_msg(void *ctx, mt_xchg_xchg *xc, const mt_proto_hdr *h, mt_span payload);
void node_sc_on_close(void *ctx, mt_xchg_xchg *xc, mt_xchg_end why);
/* Ends the running handshake: wipes it and, if close_xc, closes its exchange. */
void node_attempt_end(mt_node *n, bool close_xc);

/* Per-session side table (mt_node.c). */
mt_node_sess *node_sess_of(mt_node *n, const mt_xchg_session *s);
/* Mark the session for closing once its exchanges are done (after a response went out). */
void node_doom(mt_node *n, mt_xchg_session *s);
/* Closes doomed sessions whose exchanges are gone or whose grace ran out; returns ms until the next deadline. */
uint32_t node_reap(mt_node *n);
/* Pushes IM's per-session subscription counts to xchg (its eviction policy). */
void node_sync_subs(mt_node *n);

/* Root context, window, BOOT record (node_root.c). */
mt_err node_root_init(mt_node *n, const mt_node_cfg *cfg);
void node_window_close(mt_node *n);
uint32_t node_window_poll(mt_node *n);   /* expires a timed window; ms until its deadline */
void node_mdns_changed(mt_node *n);
/* The active verifier for a new PASE attempt; false if no window is open. */
bool node_window_verifier(const mt_node *n, mt_pase_config *cfg);
mt_err node_boot_record(mt_node *n, uint64_t *event_base);

/* BLE transport (node_btp.c). */
void node_ble_tx(mt_node *n, mt_span frame);                     /* xchg send on MT_XCHG_BTP */
void node_ble_window(mt_node *n, bool open, uint32_t window_s);  /* a BASIC window opened / the window closed */
void node_ble_off(mt_node *n);                                   /* BLE off now, before flash writes */
uint32_t node_ble_poll(mt_node *n);                              /* timers; ms until the next one */

#endif
