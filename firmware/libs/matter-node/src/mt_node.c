/* Node composition: ports -> xchg, the exchange handle table for IM, the per-session side table (attestation
 * challenge, CATs, deferred closes), init and polling. Secure Channel is in node_sc.c; the root context, window
 * and BOOT record in node_root.c; the mDNS record set in node_mdns.c. */
#include "node_priv.h"

/* ---- ports glue ---- */
static uint32_t x_now(void *ctx) { return node_now(ctx); }

static void x_send(void *ctx, mt_xchg_transport t, const mt_xchg_addr *to, mt_span frame)
{
    mt_node *n = ctx;
    if (t == MT_XCHG_UDP) n->p.udp_send(n->p.ctx, to, frame);
    else node_ble_tx(n, frame);
}

/* The transport's randomness: initial message counters, exchange ids, MRP jitter. The DRBG refuses output while a
 * due reseed fails (entropy source down), and this port cannot report an error, so the bytes then come from a
 * splitmix64 stream seeded from the DRBG at init (never zeros, never the same twice) and the failure is counted in
 * rng_failed. Key material never comes from here: the handshakes call mt_rng_fill themselves and fail with it. */
static void x_random(void *ctx, uint8_t *out, size_t len)
{
    mt_node *n = ctx;
    if (mt_rng_fill(&n->rng, out, len) == MT_OK) return;
    n->rng_failed++;
    for (size_t i = 0; i < len; i += 8) {
        uint64_t z = (n->rng_fallback += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z ^= z >> 31;
        for (size_t k = 0; k < 8 && i + k < len; k++) out[i + k] = (uint8_t)(z >> (8 * k));
    }
}

static int rng_entropy(void *ctx, uint8_t *out, size_t len)
{
    mt_node *n = ctx;
    return n->p.entropy(n->p.ctx, out, len);
}

/* ---- per-session side table, deferred closes ---- */
mt_node_sess *node_sess_of(mt_node *n, const mt_xchg_session *s)
{
    size_t i = (size_t)(s - n->xchg.sess);
    return i < MT_XCHG_N_SESSIONS ? &n->sess[i] : NULL;
}

void node_doom(mt_node *n, mt_xchg_session *s)
{
    mt_node_sess *e = node_sess_of(n, s);
    if (!e || s->kind == MT_SESS_FREE || e->doomed) return;
    e->doomed = true;
    e->doom_deadline = node_now(n) + MT_NODE_CLOSE_GRACE_MS;
}

static bool session_busy(const mt_node *n, const mt_xchg_session *s)
{
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++)
        if (n->xchg.xc[i].used && n->xchg.xc[i].session == s) return true;
    return false;
}

uint32_t node_reap(mt_node *n)
{
    uint32_t now = node_now(n), next = UINT32_MAX;
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++) {
        mt_xchg_session *s = &n->xchg.sess[i];
        mt_node_sess *e = &n->sess[i];
        if (!e->doomed) continue;
        if (s->kind == MT_SESS_FREE) { memset(e, 0, sizeof *e); continue; }
        if (e->lost) {
            mt_xchg_session_close(&n->xchg, s, MT_XCHG_END_TRANSPORT); /* keeps the fail-safe */
            continue;
        }
        if (!session_busy(n, s) || mt_due(now, e->doom_deadline)) {
            mt_xchg_session_close(&n->xchg, s, MT_XCHG_END_CLOSED);   /* on_session_close clears e */
            continue;
        }
        /* the last ack is still outstanding: look again soon (MRP retransmits run on their own timers) */
        uint32_t left = e->doom_deadline - now;
        if (left > 50) left = 50;
        if (left < next) next = left;
    }
    return next;
}

void node_sync_subs(mt_node *n)
{
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++) {
        mt_xchg_session *s = &n->xchg.sess[i];
        if (s->kind != MT_SESS_PASE && s->kind != MT_SESS_CASE) continue;
        unsigned c = mt_im_sub_count_session(&n->im, s->local_id);
        mt_xchg_session_set_subs(s, (uint8_t)(c > 255 ? 255 : c));
    }
}

/* ---- exchange handles for IM ---- */
mt_node_ex *node_ex_find(mt_node *n, const mt_xchg_xchg *xc)
{
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++)
        if (n->ex[i].xc == xc) return &n->ex[i];
    return NULL;
}

static mt_node_ex *ex_by_handle(mt_node *n, uint16_t handle)
{
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++)
        if (n->ex[i].xc && n->ex[i].handle == handle) return &n->ex[i];
    return NULL;
}

/* Handles come from a counter, so a handle is never reused while IM could still hold it (the table has
 * at most MT_XCHG_N_EXCHANGES live entries; 0xFFFF is MT_IM_NEW_EXCH). */
static mt_node_ex *ex_add(mt_node *n, mt_xchg_xchg *xc)
{
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++) {
        mt_node_ex *e = &n->ex[i];
        if (e->xc) continue;
        do n->next_handle++; while (n->next_handle == MT_IM_NEW_EXCH || ex_by_handle(n, n->next_handle));
        e->xc = xc;
        e->handle = n->next_handle;
        e->keep = false;
        return e;
    }
    return NULL;
}

static void ex_free(mt_node_ex *e) { memset(e, 0, sizeof *e); }

static mt_im_subject subject_of(const mt_xchg_session *s)
{
    mt_im_subject j;
    memset(&j, 0, sizeof j);
    j.session = s->local_id;
    j.auth = s->kind == MT_SESS_PASE ? MT_IM_AUTH_PASE : s->kind == MT_SESS_CASE ? MT_IM_AUTH_CASE : MT_IM_AUTH_NONE;
    j.fabric = s->fabric_index;
    j.node = s->kind == MT_SESS_CASE ? s->peer_node : 0;
    return j;
}

static void im_proto_msg(void *ctx, mt_xchg_xchg *xc, const mt_proto_hdr *h, mt_span payload)
{
    mt_node *n = ctx;
    mt_node_ex *e;
    mt_node_sess *se = node_sess_of(n, xc->session);
    mt_im_subject subj;
    /* The IM runs on secure sessions only (xchg already drops it on unsecured ones; this is the second guard).
     * A session marked for closing takes no new requests. */
    if ((xc->session->kind != MT_SESS_PASE && xc->session->kind != MT_SESS_CASE) || !se || se->doomed) {
        mt_xchg_close(&n->xchg, xc);
        return;
    }
    e = node_ex_find(n, xc);
    if (!e) e = ex_add(n, xc);
    if (!e) { /* cannot happen: the table is as large as the exchange table */
        mt_xchg_close(&n->xchg, xc);
        return;
    }
    e->keep = false;
    subj = subject_of(xc->session);
    if (n->p.im_trace) n->p.im_trace(n->p.ctx, false, xc->session->local_id, h->opcode, payload.len, MT_OK);
    mt_im_on_msg(&n->im, &subj, e->handle, h->opcode, payload);
    /* IM contract: no send(expect_resp) while handling means the exchange is over. The entry is still here
     * only if IM sent nothing that ended it (e.g. its reply failed for want of a frame buffer). xchg reports
     * no on_close for this handler-initiated close, so IM is told here, or state it set up for this exchange
     * (a timed window, a chunked write) would outlive it. A no-op when IM holds nothing on the exchange. */
    e = node_ex_find(n, xc);
    if (e && !e->keep) {
        uint16_t handle = e->handle;
        ex_free(e);
        mt_xchg_close(&n->xchg, xc);
        mt_im_on_exchange_failed(&n->im, handle);
    }
    /* Closes requested by root events during the invoke (RemoveFabric, CommissioningComplete, fail-safe expiry)
     * happen now if nothing is left in flight on the session, else once the response is acknowledged. */
    node_reap(n);
    node_sync_subs(n);
}

static void im_proto_close(void *ctx, mt_xchg_xchg *xc, mt_xchg_end why)
{
    mt_node *n = ctx;
    mt_node_ex *e = node_ex_find(n, xc);
    (void)why;
    if (!e) return;
    uint16_t handle = e->handle;
    ex_free(e);
    mt_im_on_exchange_failed(&n->im, handle);
}

static void on_session_close(void *ctx, const mt_xchg_session *s, mt_xchg_end why)
{
    mt_node *n = ctx;
    mt_node_sess *e = node_sess_of(n, s);
    if (s->kind == MT_SESS_PASE || s->kind == MT_SESS_CASE) mt_im_on_session_closed(&n->im, s->local_id);
    if (e) mt_wipe(e, sizeof *e);
    /* A commissioning PASE session ended on purpose (CloseSession, replaced by a new PASE, doomed, evicted): its
     * fail-safe goes with it, so a retry is not blocked by a pending fabric until the deadline (chip
     * CommissioningWindowManager::OnSessionReleased). A transport loss (MRP/idle) leaves it to the fail-safe
     * timer: SupportsConcurrentConnection is true, but a commissioner may still drop BLE after ConnectNetwork
     * and finish over CASE. A fail-safe armed over CASE for another fabric is left alone. */
    if (s->kind == MT_SESS_PASE && (why == MT_XCHG_END_CLOSED || why == MT_XCHG_END_EVICTED) &&
        mt_root_failsafe_armed(&n->root) && n->root.fs.fabric == s->fabric_index)
        mt_root_failsafe_expire(&n->root);
}

static mt_err im_send(void *ctx, uint16_t session, uint16_t *exch, uint8_t opcode, mt_span payload, bool expect_resp)
{
    mt_node *n = ctx;
    mt_xchg_xchg *xc;
    mt_node_ex *e;
    bool fresh = *exch == MT_IM_NEW_EXCH;
    mt_err err;
    if (fresh) {
        mt_xchg_session *s = mt_xchg_session_find(&n->xchg, session);
        mt_node_sess *se = s ? node_sess_of(n, s) : NULL;
        if (!s || !se || se->doomed) return MT_ERR_NOT_FOUND;
        err = mt_xchg_open(&n->xchg, s, MT_IM_PROTOCOL_ID, &xc);
        if (err) return err;
        e = ex_add(n, xc);
        if (!e) {
            mt_xchg_close(&n->xchg, xc);
            return MT_ERR_BUFFER_TOO_SMALL;
        }
    } else {
        e = ex_by_handle(n, *exch);
        if (!e) return MT_ERR_NOT_FOUND;
        xc = e->xc;
    }
    err = mt_xchg_send(&n->xchg, xc, (uint8_t)opcode, payload, true);
    if (n->p.im_trace) n->p.im_trace(n->p.ctx, true, xc->session->local_id, (uint8_t)opcode, payload.len, err);
    if (err) {
        if (fresh) {
            ex_free(e);
            mt_xchg_close(&n->xchg, xc);
        }
        return err;
    }
    if (fresh) *exch = e->handle;
    if (expect_resp) {
        e->keep = true;
    } else {
        ex_free(e);
        mt_xchg_close(&n->xchg, xc); /* deferred until the report is acknowledged */
    }
    return MT_OK;
}

static uint32_t im_now(void *ctx) { return x_now(ctx); }

/* A deferred invoke: IM sent nothing, but the exchange must outlive the handler (until mt_im_invoke_done). */
static void im_hold(void *ctx, uint16_t exch)
{
    mt_node_ex *e = ex_by_handle(ctx, exch);
    if (e) e->keep = true;
}

static const mt_im_ports k_im_ports = { im_send, im_now, im_hold };

/* ---- init ---- */
mt_err mt_node_init(mt_node *n, const mt_node_cfg *cfg)
{
    mt_err e;
    uint8_t seed[8];
    uint8_t startup[16];
    size_t sl;
    uint16_t imlen;
    uint64_t event_base;
    mt_xchg_ports xp;
    mt_im_cfg ic;
    mt_dm_cfg dc;
    uint8_t nc = 0;

    if (!cfg || !cfg->basic || !cfg->ports.now_ms || !cfg->ports.udp_send || !cfg->ports.entropy ||
        !cfg->ports.cred || !cfg->ports.kv ||
        (cfg->ports.ble_send && (!cfg->ports.ble_close || !cfg->ports.ble_window)) || cfg->n_extra_eps > MT_NODE_MAX_EXTRA_EPS || (cfg->n_extra_eps && !cfg->extra_eps) ||
        cfg->ports.cred->salt.len < 16 || cfg->ports.cred->salt.len > MT_PASE_SALT_MAX ||
        cfg->ports.cred->discriminator > MT_ADMIN_MAX_DISCRIMINATOR)
        return MT_ERR_INVALID;
    imlen = cfg->im_buf_len ? cfg->im_buf_len : MT_NODE_IM_BUF_MAX;
    if (imlen < MT_NODE_IM_BUF_MIN || imlen > MT_NODE_IM_BUF_MAX) return MT_ERR_INVALID;

    memset(n, 0, sizeof *n);
    n->p = cfg->ports;
    n->basic_cfg = cfg->basic;
    n->device_type = cfg->device_type;
    n->device_name = cfg->device_name;
    n->pairing_hint = cfg->pairing_hint;
    n->mrp_idle_ms = cfg->mrp_idle_ms ? cfg->mrp_idle_ms : MT_XCHG_IDLE_DEFAULT_MS;
    n->mrp_active_ms = cfg->mrp_active_ms ? cfg->mrp_active_ms : MT_XCHG_ACTIVE_DEFAULT_MS;
    n->boot_window_s = cfg->boot_window_s;
    n->ble_window_s = cfg->ble_window_s;
    e = mt_rng_init(&n->rng, rng_entropy, n);
    if (e) return e;
    if ((e = mt_rng_fill(&n->rng, (uint8_t *)&n->rng_fallback, sizeof n->rng_fallback))) {
        mt_rng_free(&n->rng);
        return e;
    }

    xp.ctx = n;
    xp.now_ms = x_now;
    xp.send = x_send;
    xp.random = x_random;
    mt_xchg_init(&n->xchg, &xp);
    mt_xchg_set_session_cb(&n->xchg, on_session_close, n);
    n->sc_proto.protocol_id = MT_XCHG_PROTO_SECURE_CHANNEL;
    n->sc_proto.ctx = n;
    n->sc_proto.on_msg = node_sc_on_msg;
    n->sc_proto.on_close = node_sc_on_close;
    n->im_proto.protocol_id = MT_IM_PROTOCOL_ID;
    n->im_proto.ctx = n;
    n->im_proto.on_msg = im_proto_msg;
    n->im_proto.on_close = im_proto_close;
    if ((e = mt_xchg_register(&n->xchg, &n->sc_proto)) || (e = mt_xchg_register(&n->xchg, &n->im_proto))) goto fail;

    /* Endpoint 0: Basic Information, the fabric table, and the commissioning clusters of matter-root. */
    if ((e = mt_basic_init(&n->basic, cfg->basic, n->p.kv, MT_NODE_KEY_BASIC))) goto fail;
    if ((e = node_root_init(n, cfg))) goto fail;
    /* attr_at enumerates in table order, and IM expects ascending cluster ids within an endpoint */
    n->root_clusters[nc++] = &mt_dm_descriptor;                    /* 0x1D */
    n->root_clusters[nc++] = &n->root.acl;                         /* 0x1F */
    n->root_clusters[nc++] = &n->basic.cluster;                    /* 0x28 */
    n->root_clusters[nc++] = &n->root.gencomm;                     /* 0x30 */
    if (n->p.net) n->root_clusters[nc++] = &n->netcomm.cluster;    /* 0x31 */
    n->root_clusters[nc++] = &n->gendiag.cluster;                  /* 0x33 */
    n->root_clusters[nc++] = &n->root.timesync;                    /* 0x38 */
    n->root_clusters[nc++] = &n->admin.cluster;                    /* 0x3C */
    n->root_clusters[nc++] = &n->root.opcreds;                     /* 0x3E */
    n->root_clusters[nc++] = &n->root.gkm;                         /* 0x3F */
    n->root_types[0].type = 0x0016; /* Root Node */
    n->root_types[0].revision = 2;  /* Root Node 0x0016 revision 2 (chip v1.3 data_model/device_types/RootNodeDeviceType.xml) */
    n->eps[0].id = 0;
    n->eps[0].n_types = 1;
    n->eps[0].n_clusters = nc;
    n->eps[0].types = n->root_types;
    n->eps[0].clusters = n->root_clusters;
    for (uint8_t i = 0; i < cfg->n_extra_eps; i++) n->eps[1 + i] = cfg->extra_eps[i];
    n->dmnode.eps = n->eps;
    n->dmnode.n_eps = (uint8_t)(1 + cfg->n_extra_eps);

    event_base = cfg->event_base;
    if ((e = node_boot_record(n, &event_base))) goto fail;
    n->gendiag.c.reboot_count = n->reboot_count;

    if ((e = mt_rng_fill(&n->rng, seed, sizeof seed))) goto fail;
    memset(&ic, 0, sizeof ic);
    ic.dm = &mt_dm_im;
    ic.dm_ctx = &n->dm;
    ic.port = &k_im_ports;
    ic.port_ctx = n;
    ic.tx = mt_buf_of(n->im_buf, imlen);
    ic.sub_id_seed = mt_get_le32(seed);
    ic.event_base = event_base;
    mt_im_init(&n->im, &ic);

    memset(&dc, 0, sizeof dc);
    dc.node = &n->dmnode;
    dc.im = &n->im;
    dc.access = mt_root_access;
    dc.access_ctx = &n->root;
    dc.dataver_seed = mt_get_le32(seed + 4);
    if ((e = mt_dm_init(&n->dm, &dc))) goto fail;
    mt_root_bind_dm(&n->root, &n->dm);

    /* Basic Information StartUp (critical), numbered from the persisted epoch. */
    sl = mt_basic_startup_fields(&n->basic, startup, sizeof startup);
    (void)mt_im_event_emit(&n->im, 0, MT_BASIC_CLUSTER_ID, MT_BASIC_EVENT_STARTUP, 2, mt_span_of(startup, sl), NULL);
    mt_wipe(seed, sizeof seed);

    /* Uncommissioned: the boot window opens. */
    if (mt_fabric_committed_count(&n->fabrics) == 0) mt_node_open_window(n, n->boot_window_s);
    else node_mdns_changed(n);
    return MT_OK;
fail:
    mt_rng_free(&n->rng);
    return e;
}

void mt_node_on_udp(mt_node *n, const mt_node_addr *from, uint8_t *buf, size_t len)
{
    mt_xchg_on_rx(&n->xchg, MT_XCHG_UDP, from, buf, len);
    node_reap(n);
    node_sync_subs(n);
}

uint32_t mt_node_poll(mt_node *n)
{
    uint32_t now = x_now(n), next;
    if (n->att.kind && mt_due(now, n->att.deadline)) node_attempt_end(n, true);
    next = node_window_poll(n);
    next = mt_min_u32(next, mt_root_poll(&n->root));       /* fail-safe expiry */
    if (n->p.net) next = mt_min_u32(next, mt_netcomm_poll(&n->netcomm));
    mt_gendiag_tick(&n->gendiag);
    /* IM first: its reports are sent through xchg, whose deadlines then count. */
    next = mt_min_u32(next, mt_im_poll(&n->im));
    next = mt_min_u32(next, mt_xchg_poll(&n->xchg));
    next = mt_min_u32(next, node_ble_poll(n));
    next = mt_min_u32(next, node_reap(n));
    node_sync_subs(n);
    if (n->att.kind) next = mt_min_u32(next, mt_until(now, n->att.deadline));
    return next;
}

void mt_node_net_connect_done(mt_node *n, uint8_t status, const int32_t *err)
{
    if (n->p.net) mt_netcomm_connect_done(&n->netcomm, status, err);
    node_reap(n);
}

void mt_node_net_scan_done(mt_node *n, uint8_t status)
{
    if (n->p.net) mt_netcomm_scan_done(&n->netcomm, status);
    node_reap(n);
}

bool mt_node_window_open(const mt_node *n) { return n->win.kind != MT_WINDOW_NOT_OPEN; }
bool mt_node_failsafe_armed(const mt_node *n) { return mt_root_failsafe_armed(&n->root); }
mt_err mt_node_set_utc(mt_node *n, uint64_t matter_us, uint8_t granularity, uint8_t source)
{
    return mt_root_set_utc(&n->root, matter_us, granularity, source);
}
uint32_t mt_node_utc_now(mt_node *n) { return mt_root_utc_now(&n->root); }
bool mt_node_pase_busy(const mt_node *n) { return n->att.kind == MT_SESS_PASE; }
bool mt_node_handshake_busy(const mt_node *n) { return n->att.kind != 0; }
uint16_t mt_node_reboot_count(const mt_node *n) { return n->reboot_count; }

unsigned mt_node_session_count(const mt_node *n, mt_sess_kind kind)
{
    unsigned c = 0;
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++) c += n->xchg.sess[i].kind == kind;
    return c;
}
