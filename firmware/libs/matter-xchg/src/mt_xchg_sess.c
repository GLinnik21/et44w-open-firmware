/* Session table: lookup, creation, eviction and closing. */
#include "mt_xchg_priv.h"

uint32_t xc_random32(mt_xchg *m)
{
    uint8_t b[4];
    m->p.random(m->p.ctx, b, sizeof b);
    return mt_get_le32(b);
}

mt_xchg_session *xs_find_secure(mt_xchg *m, uint16_t local_id)
{
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++)
        if (xc_secure(&m->sess[i]) && m->sess[i].local_id == local_id) return &m->sess[i];
    return NULL;
}

mt_xchg_session *xs_find_unsecured(mt_xchg *m, uint64_t peer_node, uint8_t transport)
{
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++) {
        mt_xchg_session *s = &m->sess[i];
        if (s->kind == MT_SESS_UNSECURED && s->peer_node == peer_node && s->transport == transport) return s;
    }
    return NULL;
}

bool xs_has_xchg(const mt_xchg *m, const mt_xchg_session *s)
{
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++)
        if (m->xc[i].used && m->xc[i].session == s) return true;
    return false;
}

/* Eviction class, or -1 when the session must stay. See mt_xchg.h. */
static int evict_class(const mt_xchg *m, const mt_xchg_session *s)
{
    switch (s->kind) {
    case MT_SESS_UNSECURED: return xs_has_xchg(m, s) ? -1 : 0;
    case MT_SESS_PASE:      return m->commissioning ? -1 : 1;
    case MT_SESS_CASE:      return (s->subs || xs_has_xchg(m, s)) ? 3 : 2;
    default:                return -1;
    }
}

/* A free slot, or the eviction victim of class <= max_class (then closed and freed), or NULL. */
static mt_xchg_session *slot_for_new(mt_xchg *m, int max_class)
{
    mt_xchg_session *victim = NULL;
    int best = 0;
    uint32_t best_age = 0, now = xc_now(m);
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++) {
        mt_xchg_session *s = &m->sess[i];
        int c;
        uint32_t age;
        if (s->kind == MT_SESS_FREE) return s;
        c = evict_class(m, s);
        if (c < 0 || c > max_class) continue;
        age = now - s->last_activity;
        if (!victim || c < best || (c == best && age > best_age)) { victim = s; best = c; best_age = age; }
    }
    if (victim) mt_xchg_session_close(m, victim, MT_XCHG_END_EVICTED);
    return victim;
}

static void session_init(mt_xchg *m, mt_xchg_session *s, mt_sess_kind kind, mt_xchg_transport t, const mt_xchg_addr *a)
{
    uint32_t now = xc_now(m);
    memset(s, 0, sizeof *s);
    s->kind = kind;
    s->transport = (uint8_t)t;
    s->idle_ms = MT_XCHG_IDLE_DEFAULT_MS;
    s->active_ms = MT_XCHG_ACTIVE_DEFAULT_MS;
    s->last_activity = s->last_rx = now;
    if (a) s->addr = *a;
    mt_msg_rx_init(&s->rx);
}

mt_xchg_session *xs_new_unsecured(mt_xchg *m, uint64_t peer_node, uint8_t transport, const mt_xchg_addr *from)
{
    mt_xchg_session *s = slot_for_new(m, 1);
    if (!s) return NULL;
    session_init(m, s, MT_SESS_UNSECURED, (mt_xchg_transport)transport, from);
    s->peer_node = peer_node;
    return s;
}

mt_err mt_xchg_session_id_alloc(mt_xchg *m, uint16_t *id)
{
    for (int i = 0; i < 16; i++) {
        uint16_t r = (uint16_t)xc_random32(m);
        if (r != 0 && !xs_find_secure(m, r)) { *id = r; return MT_OK; }
    }
    return MT_ERR_BUFFER_TOO_SMALL;
}

mt_err mt_xchg_session_add(mt_xchg *m, const mt_xchg_session_params *p, mt_xchg_session **out)
{
    mt_xchg_session *s;
    if ((p->kind != MT_SESS_PASE && p->kind != MT_SESS_CASE) || p->local_id == 0 || xs_find_secure(m, p->local_id))
        return MT_ERR_INVALID;
    s = slot_for_new(m, 3);
    if (!s) return MT_ERR_BUFFER_TOO_SMALL;
    session_init(m, s, p->kind, p->transport, p->addr);
    s->fabric_index = p->fabric_index;
    s->local_id = p->local_id;
    s->peer_id = p->peer_id;
    s->peer_node = p->peer_node;
    s->local_node = p->local_node;
    mt_xchg_session_set_mrp(s, p->idle_ms, p->active_ms);
    memcpy(s->enc_key, p->enc_key, MT_CCM_KEY_LEN);
    memcpy(s->dec_key, p->dec_key, MT_CCM_KEY_LEN);
    mt_msg_tx_init(&s->tx, xc_random32(m), true);
    if (out) *out = s;
    return MT_OK;
}

void mt_xchg_session_close(mt_xchg *m, mt_xchg_session *s, mt_xchg_end why)
{
    if (s->kind == MT_SESS_FREE) return;
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++)
        if (m->xc[i].used && m->xc[i].session == s) xc_free(m, &m->xc[i], why);
    if (s->kind == MT_SESS_FREE) return; /* an exchange's on_close already closed it */
    if (m->on_session_close) m->on_session_close(m->session_cb_ctx, s, why);
    memset(s, 0, sizeof *s); /* also wipes the keys */
}

mt_xchg_session *mt_xchg_session_find(mt_xchg *m, uint16_t local_id) { return xs_find_secure(m, local_id); }

void mt_xchg_session_set_subs(mt_xchg_session *s, uint8_t n) { s->subs = n; }

void mt_xchg_session_set_mrp(mt_xchg_session *s, uint32_t idle_ms, uint32_t active_ms)
{
    if (idle_ms) s->idle_ms = idle_ms < MT_XCHG_MRP_MAX_MS ? idle_ms : MT_XCHG_MRP_MAX_MS;
    if (active_ms) s->active_ms = active_ms < MT_XCHG_MRP_MAX_MS ? active_ms : MT_XCHG_MRP_MAX_MS;
}
