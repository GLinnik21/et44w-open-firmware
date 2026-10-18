/* Root context (mt_root_ops), the commissioning window (mt_admin_ops), endpoint-0 cluster setup and the BOOT
 * record. The fail-safe itself lives in matter-root; this file carries out its side effects on sessions, the
 * window and the mDNS record set. */
#include "node_priv.h"

#include "mt_tlv.h"

/* ---- root ops ---- */
static uint32_t r_now(void *ctx) { return node_now(ctx); }

static bool r_session(void *ctx, uint16_t session, mt_root_session *out)
{
    mt_node *n = ctx;
    mt_xchg_session *s = mt_xchg_session_find(&n->xchg, session);
    mt_node_sess *e = s ? node_sess_of(n, s) : NULL;
    if (!s || !e || (s->kind != MT_SESS_PASE && s->kind != MT_SESS_CASE)) return false;
    memset(out, 0, sizeof *out);
    out->auth = s->kind == MT_SESS_PASE ? MT_IM_AUTH_PASE : MT_IM_AUTH_CASE;
    out->fabric = s->fabric_index;
    out->peer_node = s->kind == MT_SESS_CASE ? s->peer_node : 0;
    memcpy(out->cats, e->cats, sizeof out->cats);
    out->n_cats = e->n_cats;
    memcpy(out->challenge, e->challenge, sizeof out->challenge);
    return true;
}

static void r_utc_set(void *ctx, uint64_t matter_us, uint8_t granularity, uint8_t source)
{
    mt_node *n = ctx;
    n->p.utc_set(n->p.ctx, matter_us, granularity, source);
}

static void r_adopt_fabric(void *ctx, uint16_t session, uint8_t fabric)
{
    mt_node *n = ctx;
    mt_xchg_session *s = mt_xchg_session_find(&n->xchg, session);
    if (s && s->kind == MT_SESS_PASE) s->fabric_index = fabric;
}

static bool r_window_open(void *ctx) { return mt_node_window_open(ctx); }

/* CommissioningComplete, before any flash write: BLE off (a flash write stalls the BLE radio's timing). Commissioning ends over CASE,
 * so no BTP session is needed past this point. */
static mt_err r_commit(void *ctx, uint8_t fabric)
{
    (void)fabric;
    node_ble_off(ctx);
    return MT_OK;
}

static mt_err r_opkey_gen(void *ctx, uint8_t priv[MT_P256_SCALAR_LEN], uint8_t pub[MT_P256_POINT_LEN])
{
    mt_node *n = ctx;
    return n->p.opkey_gen(n->p.ctx, priv, pub);
}

/* Close (after their in-flight responses) the secure sessions of `fabric` of the given kind; except = keep. */
static void doom_fabric(mt_node *n, uint8_t fabric, mt_sess_kind kind, uint16_t except)
{
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++) {
        mt_xchg_session *s = &n->xchg.sess[i];
        if (s->kind == kind && s->fabric_index == fabric && s->local_id != except) node_doom(n, s);
    }
}

/* The PASE sessions go once their last ack is in. */
static void doom_pase(mt_node *n)
{
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++)
        if (n->xchg.sess[i].kind == MT_SESS_PASE) node_doom(n, &n->xchg.sess[i]);
}

/* A fabric left the table: its sessions, subscriptions and an administrator window it opened go. */
static void fabric_gone(mt_node *n, uint8_t fabric)
{
    doom_fabric(n, fabric, MT_SESS_CASE, 0);
    doom_fabric(n, fabric, MT_SESS_PASE, 0);
    mt_im_on_fabric_removed(&n->im, fabric);
    mt_admin_fabric_removed(&n->admin, fabric);
}

static void r_event(void *ctx, mt_root_event ev, uint8_t fabric, uint16_t session, uint8_t fs_flags)
{
    mt_node *n = ctx;
    switch (ev) {
    case MT_ROOT_EV_FAILSAFE_EXPIRED:
        /* The fabric table is rolled back and Network Commissioning reverted its staged Wi-Fi (stage hook). */
        if (fs_flags & (MT_FS_ADD_NOC | MT_FS_UPDATE_NOC)) doom_fabric(n, fabric, MT_SESS_CASE, 0);
        if (fs_flags & MT_FS_ADD_NOC)
            for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++) {
                mt_xchg_session *s = &n->xchg.sess[i];
                if (s->kind == MT_SESS_PASE && s->fabric_index == fabric) s->fabric_index = 0;
            }
        /* The PASE session's implicit Administer ends with the fail-safe: it goes once its last ack is in, so an
         * ArmFailSafe(0) is still answered (chip CommissioningWindowManager, kFailSafeTimerExpired). */
        doom_pase(n);
        node_mdns_changed(n);
        break;
    case MT_ROOT_EV_FABRIC_ADDED:
        node_mdns_changed(n);
        break;
    case MT_ROOT_EV_NOC_UPDATED:
        doom_fabric(n, fabric, MT_SESS_CASE, session);
        node_mdns_changed(n);
        break;
    case MT_ROOT_EV_FABRIC_REMOVED:
        fabric_gone(n, fabric);
        /* The last fabric gone: back to the uncommissioned state, the boot window opens again. */
        if (mt_fabric_count(&n->fabrics) == 0 && !mt_node_window_open(n)) mt_node_open_window(n, n->boot_window_s);
        else node_mdns_changed(n);
        break;
    case MT_ROOT_EV_COMMISSIONED:
        /* Commissioning is over: the window closes and the PASE sessions go once their last ack is in. */
        node_window_close(n);
        doom_pase(n);
        node_mdns_changed(n);
        break;
    }
}

void mt_node_factory_reset(mt_node *n)
{
    if (mt_node_failsafe_armed(n)) mt_root_failsafe_expire(&n->root);
    while (mt_fabric_count(&n->fabrics)) {
        uint8_t fabric = mt_fabric_nth(&n->fabrics, 0)->index;
        if (mt_fabric_remove(&n->fabrics, fabric) != MT_OK) break;
        fabric_gone(n, fabric);
    }
    node_reap(n);
}

/* ---- the commissioning window ---- */
static void window_set(mt_node *n, uint8_t kind, uint32_t timeout_s, uint16_t disc, const uint8_t *w0,
                       const uint8_t *l, mt_span salt, uint32_t iterations)
{
    bool was_open = mt_node_window_open(n);
    /* A PASE attempt runs on the verifier it started with: a new window ends it. */
    if (n->att.kind == MT_SESS_PASE) node_attempt_end(n, true);
    n->win.kind = kind;
    n->win.timed = timeout_s != 0;
    n->win.deadline = node_now(n) + (timeout_s > 0x7FFFFFFFu / 1000 ? 0x7FFFFFFFu : timeout_s * 1000u);
    n->win.discriminator = disc;
    memcpy(n->win.w0, w0, sizeof n->win.w0);
    memcpy(n->win.l, l, sizeof n->win.l);
    memcpy(n->win.salt, salt.p, salt.len);
    n->win.salt_len = (uint8_t)salt.len;
    n->win.iterations = iterations;
    if (!was_open) {
        n->failed_attempts = 0;
        /* A fresh commissionable instance name per window (spec 4.3.1.1: a 64-bit random). */
        if (mt_rng_fill(&n->rng, n->win.instance, sizeof n->win.instance) != MT_OK)
            memset(n->win.instance, 0x5A, sizeof n->win.instance);
    }
    mt_xchg_set_commissioning(&n->xchg, true);
    mt_admin_window_changed(&n->admin);
    node_ble_window(n, kind == MT_WINDOW_BASIC, timeout_s);   /* BLE only with the device's own verifier */
    node_mdns_changed(n);
}

void mt_node_open_window(mt_node *n, uint32_t timeout_s)
{
    const mt_node_credentials *c = n->p.cred;
    window_set(n, MT_WINDOW_BASIC, timeout_s, c->discriminator, c->w0, c->l, c->salt, c->iterations);
}

void node_window_close(mt_node *n)
{
    if (!mt_node_window_open(n)) return;
    if (n->att.kind == MT_SESS_PASE) node_attempt_end(n, true);
    mt_wipe(&n->win, sizeof n->win);
    mt_xchg_set_commissioning(&n->xchg, false);
    mt_admin_window_changed(&n->admin);
    node_ble_window(n, false, 0);
    node_mdns_changed(n);
}

void mt_node_set_window(mt_node *n, bool open)
{
    if (open) mt_node_open_window(n, 0);
    else node_window_close(n);
}

uint32_t node_window_poll(mt_node *n)
{
    uint32_t now = node_now(n);
    if (!mt_node_window_open(n) || !n->win.timed) return UINT32_MAX;
    if (mt_due(now, n->win.deadline)) {
        node_window_close(n);
        return UINT32_MAX;
    }
    return n->win.deadline - now;
}

bool node_window_verifier(const mt_node *n, mt_pase_config *cfg)
{
    if (!mt_node_window_open(n)) return false;
    memset(cfg, 0, sizeof *cfg);
    memcpy(cfg->w0, n->win.w0, sizeof cfg->w0);
    memcpy(cfg->l, n->win.l, sizeof cfg->l);
    cfg->salt = mt_span_of(n->win.salt, n->win.salt_len);
    cfg->iterations = n->win.iterations;
    return true;
}

void node_mdns_changed(mt_node *n)
{
    if (n->p.mdns_changed) n->p.mdns_changed(n->p.ctx);
}

/* Administrator Commissioning: the enhanced window (spec 11.19.8.1; the cluster validated the fields). */
static uint8_t a_status(void *ctx) { return ((mt_node *)ctx)->win.kind; }

static mt_err a_open(void *ctx, const mt_admin_window *w)
{
    mt_node *n = ctx;
    if (w->salt.len < MT_ADMIN_SALT_MIN || w->salt.len > MT_ADMIN_SALT_MAX) return MT_ERR_INVALID;
    window_set(n, MT_WINDOW_ENHANCED, w->timeout_s, w->discriminator, w->w0, w->l, w->salt, w->iterations);
    return MT_OK;
}

static void a_close(void *ctx) { node_window_close(ctx); }

/* ---- General Diagnostics glue ---- */
static bool g_iface(void *ctx, mt_gendiag_iface *out)
{
    mt_node *n = ctx;
    return n->p.iface && n->p.iface(n->p.ctx, out);
}

mt_err node_root_init(mt_node *n, const mt_node_cfg *cfg)
{
    mt_root_cfg rc;
    mt_gendiag_cfg gc;
    mt_admin_cfg ac;
    mt_err e;

    mt_fabric_init(&n->fabrics, n->p.kv);
    if ((e = mt_fabric_load(&n->fabrics, mt_buf_of(n->work, sizeof n->work)))) return e;

    n->root_ops.now_ms = r_now;
    n->root_ops.session = r_session;
    n->root_ops.adopt_fabric = r_adopt_fabric;
    n->root_ops.window_open = r_window_open;
    n->root_ops.commit = r_commit;        /* Wi-Fi is committed by Network Commissioning's stage hook */
    n->root_ops.event = r_event;
    n->root_ops.opkey_gen = n->p.opkey_gen ? r_opkey_gen : NULL;
    n->root_ops.utc_set = n->p.utc_set ? r_utc_set : NULL;
    memset(&rc, 0, sizeof rc);
    rc.ops = &n->root_ops;
    rc.ctx = n;
    rc.fabrics = &n->fabrics;
    rc.rng = &n->rng;
    rc.creds = &n->p.cred->attest;
    rc.basic = &n->basic;
    rc.kv = n->p.kv;
    rc.kv_key = MT_NODE_KEY_REGULATORY;
    rc.location_cap = cfg->location_cap;
    rc.scratch = mt_buf_of(n->work, sizeof n->work);
    if ((e = mt_root_init(&n->root, &rc))) return e;

    n->case_cfg.fabrics = &n->fabrics;
    n->case_cfg.params.idle_ms = n->mrp_idle_ms;
    n->case_cfg.params.active_ms = n->mrp_active_ms;
    n->case_cfg.params.active_threshold_ms = MT_XCHG_ACTIVE_THRESHOLD_MS;
    n->case_cfg.params.data_model_revision = MT_BASIC_DATA_MODEL_REV;
    n->case_cfg.params.im_revision = MT_IM_REVISION;
    n->case_cfg.params.specification_version = MT_BASIC_SPEC_VERSION;
    n->case_cfg.params.max_paths_per_invoke = 1;

    memset(&gc, 0, sizeof gc);
    gc.ctx = n;
    gc.now_ms = r_now;
    gc.iface = g_iface;
    gc.boot_reason = cfg->boot_reason;
    if ((e = mt_gendiag_init(&n->gendiag, &gc))) return e;

    n->admin_ops.status = a_status;
    n->admin_ops.open = a_open;
    n->admin_ops.close = a_close;
    memset(&ac, 0, sizeof ac);
    ac.ops = &n->admin_ops;
    ac.ctx = n;
    ac.root = &n->root;
    if ((e = mt_admin_init(&n->admin, &ac))) return e;

    if (n->p.net) {
        mt_netcomm_cfg nc;
        memset(&nc, 0, sizeof nc);
        nc.net = n->p.net;
        nc.ctx = n->p.ctx;
        nc.root = &n->root;
        nc.bands = 1u << MT_WIFI_BAND_2G4;  /* RTL8720CF: 2.4 GHz only */
        nc.replace_when_full = cfg->net_replace_when_full;
        nc.scratch = mt_buf_of(n->work, sizeof n->work);
        if ((e = mt_netcomm_init(&n->netcomm, &nc))) return e;
    }
    return MT_OK;
}

/* ---- BOOT record: struct {1: reboot count, 2: first event number of the next boot} ---- */
mt_err node_boot_record(mt_node *n, uint64_t *event_base)
{
    const mt_kv_ops *kv = n->p.kv;
    uint8_t buf[32];
    size_t len = 0;
    uint32_t reboots = 0;
    uint64_t epoch = *event_base;
    bool have = false;
    mt_tlv_rd r;
    mt_tlv_wr w;
    mt_span rec;
    mt_err e;

    n->reboot_count = 0;
    if (!kv) return MT_OK;
    if (kv->get(kv->ctx, MT_NODE_KEY_BOOT, mt_buf_of(buf, sizeof buf), &len) == MT_OK) {
        mt_tlv_rd_init(&r, mt_span_of(buf, len));
        if (!mt_tlv_next(&r) && r.type == MT_TLV_STRUCT && !mt_tlv_enter(&r)) {
            bool got_r = false, got_e = false;
            while (!mt_tlv_next(&r)) {
                if (mt_tlv_is_ctx(&r, 1)) got_r = !mt_tlv_get_u32(&r, &reboots);
                else if (mt_tlv_is_ctx(&r, 2)) got_e = !mt_tlv_get_u64(&r, &epoch);
            }
            have = got_r && got_e;
        }
        if (!have) { reboots = 0; epoch = *event_base; }
    }
    /* RebootCount (spec 11.12.6.2, a best-effort count of reboots): 0 on the first boot after a factory reset,
     * +1 on every later one, saturating at the attribute's uint16. */
    if (have && reboots < 0xFFFFu) reboots++;
    n->reboot_count = (uint16_t)reboots;
    if (epoch > UINT64_MAX - MT_NODE_EPOCH_STEP) epoch = UINT64_MAX - MT_NODE_EPOCH_STEP;
    *event_base = epoch;

    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    e = mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_u(&w, mt_tlv_ctx(1), reboots);
    if (!e) e = mt_tlv_put_u(&w, mt_tlv_ctx(2), epoch + MT_NODE_EPOCH_STEP);
    if (!e) e = mt_tlv_end(&w);
    if (!e) e = mt_tlv_wr_done(&w, &rec);
    if (!e) e = kv->set(kv->ctx, MT_NODE_KEY_BOOT, rec);
    if (!e) e = kv->finish(kv->ctx, true);
    else (void)kv->finish(kv->ctx, false);
    /* A failed write is not fatal: this boot still numbers its events from the stored epoch, and the next boot
     * reuses the same numbers (controllers may then drop a few events, nothing worse). */
    return MT_OK;
}
