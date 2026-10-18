/* BLE commissioning transport: the BTP engine over the port's GATT events, the CCCD gate, one indication in flight,
 * the outgoing message queue, link timeouts and the BLE part of the BASIC window. */
#include "node_priv.h"

static bool ble_enabled(const mt_node *n) { return n->p.ble_send != NULL; }

static void q_clear(mt_node_ble *b)
{
    b->q_head = b->q_n = 0;
    b->q_sending = false;
}

/* Link state back to "not connected"; BTP sessions end as a transport loss (the fail-safe stays armed). */
static void link_gone(mt_node *n)
{
    mt_node_ble *b = &n->ble;
    bool was = b->conn;
    b->conn = b->subscribed = b->engine = b->in_flight = b->closing = false;
    b->att_mtu = 0;
    q_clear(b);
    if (!was) return;
    /* Closed by node_reap, so this is safe from inside a handler (CommissioningComplete's commit op). */
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++) {
        mt_xchg_session *s = &n->xchg.sess[i];
        if (s->kind != MT_SESS_FREE && s->transport == MT_XCHG_BTP) {
            node_doom(n, s);
            n->sess[i].lost = true;
        }
    }
}

static void link_close(mt_node *n, mt_node_ble_close why)
{
    mt_node_ble *b = &n->ble;
    if (!b->conn || b->closing) return;
    b->closing = true;
    b->close_why = (uint8_t)why;
    n->p.ble_close(n->p.ctx);
}

/* A BTP session the commissioner still uses (a handshake on BTP counts too). */
static bool btp_in_use(const mt_node *n)
{
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++) {
        const mt_xchg_session *s = &n->xchg.sess[i];
        if (s->transport == MT_XCHG_BTP && (s->kind == MT_SESS_PASE || s->kind == MT_SESS_CASE)) return true;
    }
    return n->att.kind && n->att.xc && n->att.xc->session->transport == MT_XCHG_BTP;
}

/* The window part is over: off now if idle; a link carrying a session stays until it disconnects. */
static void settle(mt_node *n)
{
    mt_node_ble *b = &n->ble;
    if (b->want || !b->on) return;
    if (!b->conn) {
        b->on = false;
        n->p.ble_window(n->p.ctx, false);
    } else if (!btp_in_use(n)) {
        link_close(n, MT_NODE_BLE_CLOSE_IDLE);
    }
}

/* Moves data: queued message -> engine -> one indication, while the CCCD is on and nothing is unconfirmed. */
static void pump(mt_node *n)
{
    mt_node_ble *b = &n->ble;
    if (!b->conn || !b->engine || b->closing) return;
    for (;;) {
        if (mt_btp_closed(&b->btp)) {
            link_close(n, MT_NODE_BLE_CLOSE_BTP_CLOSED);
            return;
        }
        if (b->q_sending && mt_btp_tx_idle(&b->btp)) {
            b->q_sending = false;
            b->q_head = (uint8_t)((b->q_head + 1) % MT_NODE_BLE_TXQ);
            b->q_n--;
        }
        if (!b->q_sending && b->q_n && mt_btp_open(&b->btp)) {
            if (mt_btp_send(&b->btp, mt_span_of(b->q[b->q_head], b->q_len[b->q_head])) != MT_OK) {
                link_close(n, MT_NODE_BLE_CLOSE_BTP_SEND);
                return;
            }
            b->q_sending = true;
        }
        if (!b->subscribed || b->in_flight) return;
        size_t len = mt_btp_poll(&b->btp, node_now(n), mt_buf_of(b->pkt, sizeof b->pkt));
        if (!len) {
            if (mt_btp_closed(&b->btp)) continue;
            return;
        }
        if (!n->p.ble_send(n->p.ctx, mt_span_of(b->pkt, len))) {
            link_close(n, MT_NODE_BLE_CLOSE_PORT_SEND);
            return;
        }
        b->in_flight = true;
        b->sent_at = node_now(n);
    }
}

void node_ble_tx(mt_node *n, mt_span frame)
{
    mt_node_ble *b = &n->ble;
    if (!ble_enabled(n) || !b->conn || b->closing) return;
    if (b->q_n == MT_NODE_BLE_TXQ || frame.len > sizeof b->q[0]) {
        /* No MRP on BTP: a dropped message would stall the commissioner, so the link goes instead (it retries). */
        link_close(n, MT_NODE_BLE_CLOSE_QUEUE);
        return;
    }
    uint8_t slot = (uint8_t)((b->q_head + b->q_n) % MT_NODE_BLE_TXQ);
    memcpy(b->q[slot], frame.p, frame.len);
    b->q_len[slot] = (uint16_t)frame.len;
    b->q_n++;
    pump(n);
}

static void on_write(mt_node *n, mt_span data)
{
    mt_node_ble *b = &n->ble;
    bool first = !b->engine;
    if (b->closing) return;
    if (first) {
        mt_btp_init(&b->btp, mt_buf_of(b->rx, sizeof b->rx), b->att_mtu);
        b->engine = true;
    }
    if (mt_btp_rx(&b->btp, node_now(n), data) != MT_OK) {
        link_close(n, MT_NODE_BLE_CLOSE_RX);
        return;
    }
    if (first && b->att_mtu) mt_btp_limit_mtu(&b->btp, b->att_mtu);
    mt_span m = mt_btp_msg(&b->btp);
    if (m.len) {
        /* Decrypted in place in our reassembly buffer, released before the next message can start. */
        mt_xchg_on_rx(&n->xchg, MT_XCHG_BTP, NULL, b->rx, m.len);
        mt_btp_msg_release(&b->btp);
        node_reap(n);
        node_sync_subs(n);
    }
    pump(n);
}

void mt_node_on_ble(mt_node *n, mt_node_ble_ev ev, mt_span data, uint16_t val)
{
    mt_node_ble *b = &n->ble;
    if (!ble_enabled(n)) return;
    switch (ev) {
    case MT_NODE_BLE_CONNECTED:
        if (b->conn) link_gone(n);
        b->conn = true;
        b->conn_at = node_now(n);
        b->close_why = MT_NODE_BLE_CLOSE_NONE;
        if (!b->on) link_close(n, MT_NODE_BLE_CLOSE_LATE);      /* a late connect after BLE was asked off */
        break;
    case MT_NODE_BLE_MTU:
        if (b->conn && !b->engine) b->att_mtu = val;
        break;
    case MT_NODE_BLE_SUBSCRIBED:
    case MT_NODE_BLE_UNSUBSCRIBED:
        if (!b->conn) break;
        b->subscribed = ev == MT_NODE_BLE_SUBSCRIBED;
        /* Unsubscribing after the handshake ends BTP (spec 4.19.3.4: the central closes by unsubscribing). */
        if (!b->subscribed && b->engine) link_close(n, MT_NODE_BLE_CLOSE_UNSUB);
        else pump(n);
        break;
    case MT_NODE_BLE_WRITE:
        if (b->conn) on_write(n, data);
        break;
    case MT_NODE_BLE_SENT:
        if (!b->conn || !b->in_flight) break;
        b->in_flight = false;
        if (val) link_close(n, MT_NODE_BLE_CLOSE_NACK);
        else pump(n);
        break;
    case MT_NODE_BLE_DISCONNECTED:
        link_gone(n);
        settle(n);
        break;
    }
    node_reap(n);
    node_sync_subs(n);
}

/* A BASIC window opened (open) or the window closed / turned enhanced (!open). */
void node_ble_window(mt_node *n, bool open, uint32_t window_s)
{
    mt_node_ble *b = &n->ble;
    if (!ble_enabled(n)) return;
    if (open) {
        uint32_t s = n->ble_window_s;
        if (window_s && (!s || window_s < s)) s = window_s;
        b->want = true;
        b->timed = s != 0;
        b->deadline = node_now(n) + (s > 0x7FFFFFFFu / 1000 ? 0x7FFFFFFFu : s * 1000u);
        if (!b->on) {
            b->on = true;
            n->p.ble_window(n->p.ctx, true);
        }
        return;
    }
    b->want = false;
    settle(n);
}

void node_ble_off(mt_node *n)
{
    mt_node_ble *b = &n->ble;
    if (!ble_enabled(n)) return;
    b->want = false;
    if (b->on) {
        b->on = false;
        n->p.ble_window(n->p.ctx, false);
    }
    link_gone(n);
}

uint32_t node_ble_poll(mt_node *n)
{
    mt_node_ble *b = &n->ble;
    uint32_t now, next = UINT32_MAX;
    if (!ble_enabled(n)) return next;
    now = node_now(n);
    if (b->want && b->timed) {
        if (mt_due(now, b->deadline)) node_ble_window(n, false, 0);
        else next = b->deadline - now;
    }
    if (b->on && !b->want) settle(n);
    if (!b->conn || b->closing) return next;
    /* Connected: the handshake must complete with C2 subscribed, and the central must confirm indications. */
    if (!b->engine || !b->subscribed || !mt_btp_open(&b->btp)) {
        uint32_t end = b->conn_at + MT_NODE_BLE_HS_MS;
        if (mt_due(now, end)) {
            link_close(n, MT_NODE_BLE_CLOSE_HS_TIMEOUT);
            return next;
        }
        if (end - now < next) next = end - now;
    }
    if (b->in_flight) {
        uint32_t end = b->sent_at + MT_NODE_BLE_CONFIRM_MS;
        if (mt_due(now, end)) {
            link_close(n, MT_NODE_BLE_CLOSE_CONFIRM_TIMEOUT);
            return next;
        }
        if (end - now < next) next = end - now;
    } else if (b->engine) {
        pump(n);                                   /* runs the engine's ack timers */
        if (b->conn && !b->closing && b->subscribed && !b->in_flight) {
            uint32_t w = mt_btp_wait_ms(&b->btp, node_now(n));
            if (w < next) next = w;
        }
    }
    return next;
}

bool mt_node_ble_on(const mt_node *n) { return n->ble.on; }
bool mt_node_ble_connected(const mt_node *n) { return n->ble.conn; }
mt_node_ble_close mt_node_ble_close_why(const mt_node *n) { return (mt_node_ble_close)n->ble.close_why; }
