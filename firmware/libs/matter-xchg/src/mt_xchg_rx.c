/* Receive path: session lookup, open, replay check, MRP bookkeeping, dispatch (spec 4.10, 4.12). */
#include "mt_xchg_priv.h"

void mt_xchg_on_rx(mt_xchg *m, mt_xchg_transport t, const mt_xchg_addr *from, uint8_t *frame, size_t len)
{
    mt_msg_hdr h;
    mt_proto_hdr ph;
    mt_xchg_session *s;
    mt_xchg_xchg *xc;
    const mt_xchg_proto *proto;
    size_t hl, poff, plen, pl;
    uint32_t now;
    mt_err e;
    bool peer_init, standalone, reliable;

    if (mt_msg_hdr_decode(mt_span_of(frame, len), &h, &hl) != MT_OK) return;
    if (h.session_id == 0) {
        if (!h.has_src || h.dsiz == MT_MSG_DSIZ_GROUP) return; /* unsecured: the initiator names itself */
        s = xs_find_unsecured(m, h.src, (uint8_t)t);
        poff = hl;
        plen = len - hl;
    } else {
        s = xs_find_secure(m, h.session_id);
        if (!s || s->transport != (uint8_t)t) {
            m->rx_no_session++;
            return;
        }
        poff = hl;
        if (mt_msg_open_decoded(s->dec_key, s->peer_node, frame, len, &h, hl, &plen) != MT_OK) {
            m->rx_bad_mic++;
            return;
        }
    }
    if (mt_proto_hdr_decode(mt_span_of(frame + poff, plen), &ph, &pl) != MT_OK) return;
    if (ph.vendor_id != 0) return;
    /* Unsecured sessions exist for session establishment only (spec 4.13): any other protocol on session 0,
     * e.g. an IM request, is dropped unacknowledged before it can create a session or an exchange. */
    if (h.session_id == 0 && ph.protocol_id != MT_XCHG_PROTO_SECURE_CHANNEL) return;

    peer_init = (ph.flags & MT_XCHG_INITIATOR) != 0;
    standalone = ph.protocol_id == MT_XCHG_PROTO_SECURE_CHANNEL && ph.opcode == MT_XCHG_OP_STANDALONE_ACK;
    proto = xc_find_proto(m, ph.protocol_id);
    xc = s ? xc_find(m, s, ph.exchange_id, !peer_init) : NULL;
    /* Out of exchange slots: drop before the counter is recorded so the peer's retransmit is not taken for a
     * duplicate and acknowledged. */
    if (!xc && peer_init && !standalone && proto && !xc_have_free(m)) return;
    if (!s) { /* only a new handshake opens an unsecured session (we never initiate on one) */
        if (!peer_init || standalone || !proto) return;
        s = xs_new_unsecured(m, h.src, (uint8_t)t, from);
        if (!s) return;
    }

    e = mt_msg_rx_accept(&s->rx, h.counter, xc_secure(s) ? MT_MSG_RX_SECURE : MT_MSG_RX_UNSECURED);
    now = xc_now(m);
    reliable = xc_mrp(s) && (ph.flags & MT_XCHG_RELIABLE);
    if (e == MT_ERR_DUPLICATE) { /* the peer missed our ack: repeat it, deliver nothing */
        if (reliable) xc_send_ack(m, s, ph.exchange_id, !peer_init, h.counter);
        return;
    }
    if (e != MT_OK) return; /* stale */
    s->last_activity = s->last_rx = now;
    if (t == MT_XCHG_UDP && from) s->addr = *from;

    if (xc && xc_mrp(s) && (ph.flags & MT_XCHG_ACK)) xc_on_ack(m, xc, ph.ack_counter); /* may release a closing one */
    if (standalone) return;
    /* A message from the peer on the exchange that carries no ack flag: if it is the reply to our reliable
     * message, the peer demonstrably has it, and its standalone ack was lost. Waiting for the retransmit's ack
     * would stall the next send (IM chunking) for no benefit, so count it as the ack. A peer that acks
     * piggybacked always sets the flag, so only the flagless case is covered. */
    if (xc && xc->used && xc_mrp(s) && xc_awaiting(xc) && !(ph.flags & MT_XCHG_ACK)) xc_on_ack(m, xc, xc->tx_counter);
    if (xc && (!xc->used || xc->closing)) { /* we already let go of it: only keep the peer quiet */
        if (reliable) xc_send_ack(m, s, ph.exchange_id, !peer_init, h.counter);
        return;
    }
    if (!xc && peer_init && proto) xc = xc_alloc(m, s, ph.exchange_id, false, proto);
    if (!xc) { /* unknown protocol, or a reply to an exchange that is gone */
        if (reliable) xc_send_ack(m, s, ph.exchange_id, !peer_init, h.counter);
        return;
    }
    xc->last_activity = now;
    if (reliable) {
        if (xc->ack_pending) xc_send_ack(m, s, xc->id, xc->initiator, xc->ack_counter); /* never hold two */
        xc->ack_pending = true;
        xc->ack_counter = h.counter;
        xc->ack_due = now + MT_XCHG_ACK_TIMEOUT_MS;
    }
    xc->proto->on_msg(xc->proto->ctx, xc, &ph, mt_span_of(frame + poff + pl, plen - pl));
}
