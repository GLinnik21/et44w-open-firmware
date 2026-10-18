/* BLE commissioning (the BLE window, BLE off at CommissioningComplete before any flash write): the node over a fake BLE link whose central side is matter-btp's
 * own central engine, so both ends of BTP run. Included into test_node.c (shares its world, clients and invoke
 * helpers). The fake port is strict: it fails the test if a second indication is sent before the first is
 * confirmed, and it records what was in flash (Wi-Fi saves, fabric commits) at the moment BLE was turned off. */

/* ---- fake Wi-Fi port (Network Commissioning) ---- */
typedef struct {
    bool on, pending;
    uint8_t ssid[32], saved_ssid[32];
    size_t len, saved_len;
    int saves, connects, reverts;
} netf;
static netf NF;
static bool nf_saved(void *c, uint8_t s[32], size_t *l)
{
    (void)c;
    if (!NF.saved_len) return false;
    memcpy(s, NF.saved_ssid, NF.saved_len);
    *l = NF.saved_len;
    return true;
}
static mt_err nf_save(void *c, mt_span ssid, mt_span cred)
{
    (void)c;
    (void)cred;
    memcpy(NF.saved_ssid, ssid.p, ssid.len);
    NF.saved_len = ssid.len;
    NF.saves++;
    return MT_OK;
}
static mt_err nf_erase(void *c) { (void)c; NF.saved_len = 0; return MT_OK; }
static bool nf_connected(void *c, uint8_t s[32], size_t *l)
{
    (void)c;
    if (!NF.on) return false;
    memcpy(s, NF.ssid, NF.len);
    *l = NF.len;
    return true;
}
static mt_err nf_connect(void *c, mt_span ssid, const mt_span *cred)
{
    (void)c;
    (void)cred;
    memcpy(NF.ssid, ssid.p, ssid.len);
    NF.len = ssid.len;
    NF.on = false;
    NF.pending = true;   /* answered from the harness, never inside the op */
    NF.connects++;
    return MT_OK;
}
static void nf_revert(void *c) { (void)c; NF.reverts++; NF.on = false; }
static mt_err nf_scan(void *c, mt_span ssid) { (void)c; (void)ssid; return MT_ERR_UNSUPPORTED; }
static bool nf_scan_result(void *c, uint16_t idx, mt_netctl_ap *out) { (void)c; (void)idx; (void)out; return false; }
static const mt_netctl_ops NFO = { nf_saved, nf_save, nf_erase, nf_connected, NULL, nf_connect, nf_revert, nf_scan,
                                   nf_scan_result, NULL, NULL };

/* ---- fake BLE port + central ---- */
#define BQ 4
typedef struct {
    bool on;                  /* advertising/stack on, as the node asked */
    unsigned window_on, window_off, closes;
    bool close_req;
    bool linked;              /* central engine open */
    bool connected;
    uint8_t ind[MT_BTP_MAX_FRAG];
    size_t ind_n;             /* an indication in flight, 0 = none */
    unsigned sends, overlap;  /* indications; second one while the first was unconfirmed (must stay 0) */
    bool hold_confirm;        /* test knob: do not confirm the indication in flight */
    mt_btp c;
    uint8_t crx[1400];
    uint8_t out[BQ][TI_FRAME_MAX];   /* central -> node messages waiting for the central engine */
    size_t out_n[BQ];
    int oh, ot;
    bool out_busy;
    cli cl;                   /* the commissioner on BLE: q = messages the central received */
    int saves_at_off;         /* NF.saves and committed fabrics when BLE went off (-1 = not yet) */
    int fabrics_at_off;
} blef;
static blef BL;

static bool bp_send(void *c, mt_span pkt)
{
    (void)c;
    if (BL.ind_n) BL.overlap++;
    CHECK(pkt.len <= sizeof BL.ind);
    memcpy(BL.ind, pkt.p, pkt.len);
    BL.ind_n = pkt.len;
    BL.sends++;
    return true;
}
static void bp_close(void *c) { (void)c; BL.closes++; BL.close_req = true; }
static void bp_window(void *c, bool open)
{
    (void)c;
    BL.on = open;
    if (open) { BL.window_on++; return; }
    BL.window_off++;
    BL.saves_at_off = NF.saves;
    BL.fabrics_at_off = (int)mt_fabric_committed_count(&N->fabrics);
    BL.connected = BL.linked = false;   /* the radio is off: the link is gone without an event */
    BL.ind_n = 0;
}

static void ble_ev(mt_node_ble_ev ev, mt_span d, uint16_t v) { mt_node_on_ble(N, ev, d, v); }

static void ble_disconnect(void)
{
    BL.connected = BL.linked = false;
    BL.close_req = false;
    BL.ind_n = 0;
    BL.oh = BL.ot = 0;
    BL.out_busy = false;
    ble_ev(MT_NODE_BLE_DISCONNECTED, mt_span_of(NULL, 0), 0);
}

/* Runs the fake link until nothing moves: confirmations, central -> node writes, delivered messages. */
static void ble_pump(void)
{
    uint8_t pk[MT_BTP_MAX_FRAG];
    for (int guard = 0; guard < 20000; guard++) {
        bool did = false;
        if (BL.close_req) {
            ble_disconnect();
            return;
        }
        if (!BL.connected) return;
        if (BL.ind_n && !BL.hold_confirm) {
            size_t n = BL.ind_n;
            memcpy(pk, BL.ind, n);
            BL.ind_n = 0;
            if (!BL.linked) {
                CHECK(mt_btp_central_open(&BL.c, mt_buf_of(BL.crx, sizeof BL.crx), now, mt_span_of(pk, n)) == MT_OK);
                BL.linked = true;
            } else {
                CHECK(mt_btp_rx(&BL.c, now, mt_span_of(pk, n)) == MT_OK);
                mt_span m = mt_btp_msg(&BL.c);
                if (m.len) {
                    cli *d = &BL.cl;
                    CHECK((d->qt + 1) % MAXQ != d->qh);
                    memcpy(d->q[d->qt].f, m.p, m.len);
                    d->q[d->qt].n = m.len;
                    d->qt = (d->qt + 1) % MAXQ;
                    mt_btp_msg_release(&BL.c);
                }
            }
            ble_ev(MT_NODE_BLE_SENT, mt_span_of(NULL, 0), 0);
            did = true;
        }
        if (!BL.connected) return;
        if (BL.linked) {
            if (BL.out_busy && mt_btp_tx_idle(&BL.c)) {
                BL.out_busy = false;
                BL.oh = (BL.oh + 1) % BQ;
            }
            if (!BL.out_busy && BL.oh != BL.ot) {
                CHECK(mt_btp_send(&BL.c, mt_span_of(BL.out[BL.oh], BL.out_n[BL.oh])) == MT_OK);
                BL.out_busy = true;
            }
            size_t n = mt_btp_poll(&BL.c, now, mt_buf_of(pk, sizeof pk));
            if (n) {
                ble_ev(MT_NODE_BLE_WRITE, mt_span_of(pk, n), 0);
                did = true;
            }
            CHECK(!mt_btp_closed(&BL.c));
        }
        if (!did) return;
    }
    CHECK(!"ble_pump did not settle");
}

static void b_send(void *ctx, const uint8_t *frame, size_t len)
{
    (void)ctx;
    if (!BL.connected) return;
    CHECK((BL.ot + 1) % BQ != BL.oh && len <= TI_FRAME_MAX);
    memcpy(BL.out[BL.ot], frame, len);
    BL.out_n[BL.ot] = len;
    BL.ot = (BL.ot + 1) % BQ;
    ble_pump();
}

static size_t b_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t wait_ms)
{
    cli *d = ctx;
    ble_pump();
    if (d->qh == d->qt) {
        if (NF.pending) {      /* the Wi-Fi join finishes while the commissioner waits */
            NF.pending = false;
            NF.on = true;
            mt_node_net_connect_done(N, 0, NULL);
        } else {
            now += wait_ms;
            mt_node_poll(N);
        }
        ble_pump();
    }
    if (d->qh == d->qt) return 0;
    size_t n = d->q[d->qh].n;
    if (n > cap) n = cap;
    memcpy(buf, d->q[d->qh].f, n);
    d->qh = (d->qh + 1) % MAXQ;
    return n;
}

/* A central connects, negotiates `mtu`, writes the handshake request; subscribes unless !subscribe. */
static void ble_connect(uint16_t mtu, bool subscribe)
{
    uint8_t req[MT_BTP_HS_REQ_LEN];
    if (BL.cl.port) ti_free(&BL.cl.t);
    memset(&BL.cl, 0, sizeof BL.cl);
    BL.cl.port = 0xB1E;
    BL.cl.ent = 0xB1E5EED;
    ti_io io = { &BL.cl, b_send, b_recv };
    ti_init(&BL.cl.t, io, ent_fn, &BL.cl.ent);
    BL.connected = true;
    BL.linked = false;
    BL.ind_n = 0;
    BL.oh = BL.ot = 0;
    BL.out_busy = false;
    unsigned sends = BL.sends;
    ble_ev(MT_NODE_BLE_CONNECTED, mt_span_of(NULL, 0), 0);
    ble_ev(MT_NODE_BLE_MTU, mt_span_of(NULL, 0), mtu);
    size_t n = mt_btp_hs_request(req, 247, 4);   /* iOS reports 247 whatever the link got */
    ble_ev(MT_NODE_BLE_WRITE, mt_span_of(req, n), 0);
    /* CCCD gate: nothing is indicated before the central subscribes to C2 */
    CHECK(BL.ind_n == 0 && BL.sends == sends);
    if (!subscribe) return;
    ble_ev(MT_NODE_BLE_SUBSCRIBED, mt_span_of(NULL, 0), 0);
    CHECK(BL.ind_n == 6);
    ble_pump();
    CHECK(BL.linked && mt_btp_frag_size(&BL.c) == (mtu < 247 ? mtu - 3 : 244));
}

static void ble_world(uint32_t ble_window_s)
{
    memset(&NF, 0, sizeof NF);
    if (BL.cl.port) ti_free(&BL.cl.t);
    memset(&BL, 0, sizeof BL);
    BL.saves_at_off = BL.fabrics_at_off = -1;
    g_ble = true;
    g_ble_window_s = ble_window_s;
    g_opkey_gen = opkey_device;
    world(0);
}
static void ble_world_end(void)
{
    if (BL.cl.port) ti_free(&BL.cl.t);
    BL.cl.port = 0;
    g_ble = false;
    g_opkey_gen = NULL;
}

enum { NCM = 0x31, NC_ADD_WIFI = 2, NC_CONFIG_RESP = 5, NC_CONNECT = 6, NC_CONNECT_RESP = 7 };
static void f_wifi(mt_tlv_wr *w)
{
    mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of((const uint8_t *)"home", 4));
    mt_tlv_put_bytes(w, mt_tlv_ctx(1), mt_span_of((const uint8_t *)"password1", 9));
    mt_tlv_put_u(w, mt_tlv_ctx(2), 7);
}
static void f_connect(mt_tlv_wr *w)
{
    mt_tlv_put_bytes(w, mt_tlv_ctx(0), mt_span_of((const uint8_t *)"home", 4));
    mt_tlv_put_u(w, mt_tlv_ctx(1), 8);
}

/* The whole commissioning flow of an iPhone: BLE + PASE, read, ArmFailSafe, CSR/AddRoot/AddNOC, Wi-Fi, the BLE
 * link drops after ConnectNetwork, CASE over IP, CommissioningComplete. */
static void test_ble_commissioning(void)
{
    inv_res r;
    mt_fabric copy;
    ti_report *rep = (ti_report *)calloc(1, sizeof *rep);
    ble_world(900);
    CHECK(BL.on && BL.window_on == 1 && mt_node_ble_on(N));
    ble_connect(185, true);

    ti *t = &BL.cl.t;
    CHECK(ti_pase(t, PASSCODE, NULL) == MT_OK);
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 1);
    CHECK(N->xchg.sess[0].transport == MT_XCHG_BTP || N->xchg.sess[1].transport == MT_XCHG_BTP);
    /* a wildcard read of endpoint 0: many chunks, each a multi-segment BTP message */
    CHECK(ti_read(t, (ti_path[]){ P(0, -1, -1) }, 1, rep) == MT_OK && rep->chunks >= 1 && !rep->overflow);
    CHECK(ti_find(rep, 0, 0x28, 2) && ti_find(rep, 0, 0x28, 2)->val == 0xFFF1);   /* VendorID */
    const mt_fabric *f = commission_to_addnoc(t, 120, false);
    CHECK(f != NULL);
    if (!f) { free(rep); ble_world_end(); return; }
    copy = *f;
    CHECK(invoke(t, 0, NCM, NC_ADD_WIFI, f_wifi, &r) == MT_OK && r.status == -1 && r.cmd == NC_CONFIG_RESP &&
          r.f0 == 0);
    CHECK(invoke(t, 0, NCM, NC_CONNECT, f_connect, &r) == MT_OK && r.status == -1 && r.cmd == NC_CONNECT_RESP &&
          r.f0 == 0);
    CHECK(NF.connects == 1 && NF.on && NF.saves == 0);
    CHECK(BL.overlap == 0 && BL.sends > 20);

    /* the commissioner drops BLE: the PASE session goes as a transport loss, the fail-safe and the pending fabric
     * stay, BLE advertises again (still in the window) */
    ble_disconnect();
    CHECK(mt_node_session_count(N, MT_SESS_PASE) == 0);
    CHECK(mt_root_failsafe_armed(&N->root) && mt_fabric_pending(&N->fabrics) != NULL);
    CHECK(BL.on && BL.window_off == 0 && !mt_node_ble_connected(N));
    settle(2000);
    CHECK(mt_root_failsafe_armed(&N->root) && NF.reverts == 0);

    /* CASE over IP, then CommissioningComplete: BLE is off before anything is written */
    cli_start(1);
    CHECK(ci_case(&C[1].t, &copy) == MT_OK);
    CHECK(invoke(&C[1].t, 0, GC, GC_COMPLETE, NULL, &r) == MT_OK && r.status == -1 && r.cmd == GC_COMPLETE_RESP &&
          r.f0 == 0);
    CHECK(BL.window_off == 1 && !BL.on && !mt_node_ble_on(N));
    CHECK(BL.saves_at_off == 0 && BL.fabrics_at_off == 0);   /* nothing was in flash yet */
    CHECK(NF.saves == 1 && mt_fabric_committed_count(&N->fabrics) == 1 && !mt_node_window_open(N));
    settle(11000);
    CHECK(mt_node_session_count(N, MT_SESS_CASE) == 1 && BL.window_on == 1);

    /* commissioned: a reboot starts without BLE */
    reboot_node(0);
    CHECK(BL.window_on == 1 && !mt_node_ble_on(N));
    free(rep);
    ble_world_end();
}

/* The commissioner drops BLE mid-way, before Wi-Fi: the fail-safe still runs out on its own timer. */
static void test_ble_drop_keeps_failsafe(void)
{
    ble_world(900);
    ble_connect(247, true);
    CHECK(commission_to_addnoc(&BL.cl.t, 30, false) != NULL);
    ble_disconnect();
    CHECK(mt_root_failsafe_armed(&N->root) && mt_fabric_pending(&N->fabrics) != NULL);
    settle(31000);
    CHECK(!mt_root_failsafe_armed(&N->root) && mt_fabric_pending(&N->fabrics) == NULL);
    /* a second commissioner can start over on BLE */
    ble_connect(247, true);
    CHECK(ti_pase(&BL.cl.t, PASSCODE, NULL) == MT_OK);
    ble_world_end();
}

/* Link policing: handshake timeout, no subscription, unconfirmed indications, a PASE attempt cut by a disconnect. */
static void test_ble_link_rules(void)
{
    ble_world(900);
    /* connected, never writes: dropped after MT_NODE_BLE_HS_MS */
    BL.connected = true;
    ble_ev(MT_NODE_BLE_CONNECTED, mt_span_of(NULL, 0), 0);
    settle(MT_NODE_BLE_HS_MS - 200);
    CHECK(BL.closes == 0);
    settle(400);
    CHECK(BL.closes == 1);
    ble_pump();
    CHECK(!mt_node_ble_connected(N) && BL.on);

    /* handshake written, never subscribed: dropped too, nothing ever indicated */
    ble_connect(247, false);
    settle(MT_NODE_BLE_HS_MS + 200);
    CHECK(BL.closes == 2 && BL.sends == 0);
    ble_pump();

    /* unsubscribing after the handshake ends BTP (spec 4.19.3.4) */
    ble_connect(247, true);
    ble_ev(MT_NODE_BLE_UNSUBSCRIBED, mt_span_of(NULL, 0), 0);
    CHECK(BL.closes == 3);
    ble_pump();

    /* a PASE attempt over BLE cut by a disconnect ends the attempt (the next one is not BUSY) */
    ble_connect(247, true);
    CHECK(ti_pase_params_only(&BL.cl.t) == MT_OK && mt_node_pase_busy(N));
    ble_disconnect();
    CHECK(!mt_node_pase_busy(N));
    /* the handshake response is never confirmed: dropped after MT_NODE_BLE_CONFIRM_MS (not the handshake timer:
     * the handshake is done and C2 subscribed) */
    ble_connect(247, false);
    BL.hold_confirm = true;
    ble_ev(MT_NODE_BLE_SUBSCRIBED, mt_span_of(NULL, 0), 0);
    CHECK(BL.ind_n == 6);
    settle(MT_NODE_BLE_CONFIRM_MS - 200);
    CHECK(BL.closes == 4 - 1);
    settle(400);
    CHECK(BL.closes == 4 && BL.overlap == 0);
    BL.hold_confirm = false;
    ble_pump();
    CHECK(!mt_node_ble_connected(N) && !mt_node_pase_busy(N));
    ble_world_end();
}

/* The BLE part of the window: off after ble_window_s while the (on-network) window stays; a link carrying PASE
 * outlives it until it disconnects; one without a session is dropped. */
static void test_ble_window(void)
{
    ble_world(60);
    settle(59000);
    CHECK(BL.on && BL.window_off == 0);
    settle(2000);
    CHECK(!BL.on && BL.window_off == 1 && mt_node_window_open(N));
    CHECK(!mt_node_ble_on(N));

    ble_world(60);
    ble_connect(247, true);
    CHECK(ti_pase(&BL.cl.t, PASSCODE, NULL) == MT_OK);
    pase_hold(&BL.cl.t);
    settle(61000);
    CHECK(BL.on && BL.closes == 0 && mt_node_session_count(N, MT_SESS_PASE) == 1);  /* in use: kept */
    ble_disconnect();
    CHECK(!BL.on && BL.window_off == 1);
    CHECK(mt_root_failsafe_armed(&N->root));   /* a transport loss, not a close */

    ble_world(60);
    ble_connect(247, true);
    settle(61000);
    CHECK(BL.closes == 1);                     /* no session on the link: dropped */
    ble_pump();
    CHECK(!BL.on && BL.window_off == 1);

    /* an enhanced window does not use BLE; a late connect after BLE went off is dropped */
    ble_world(0);
    CHECK(BL.on);
    mt_node_set_window(N, false);
    CHECK(!BL.on && BL.window_off == 1);
    BL.connected = true;
    ble_ev(MT_NODE_BLE_CONNECTED, mt_span_of(NULL, 0), 0);
    CHECK(BL.closes == 1);
    ble_pump();
    /* reopening the basic window asks the port again (the AmebaZ2 port reboots for it) */
    mt_node_open_window(N, 0);
    CHECK(BL.on && BL.window_on == 2);
    ble_world_end();
}

/* The upgrade case: commissioned on-network (matter.js, no BLE link ever), then a BLE-capable image boots on it.
 * With a committed fabric the port must never be asked to turn BLE on, however long the node runs; the uncommissioned
 * boot before it asked once and turned it off at CommissioningComplete. */
static void test_ble_commissioned_boot(void)
{
    inv_res r;
    mt_fabric copy;
    ble_world(900);
    CHECK(BL.on && BL.window_on == 1);
    cli_start(0);
    cli_start(1);
    const mt_fabric *f = commission_to_addnoc(&C[0].t, 120, false);
    CHECK(f != NULL);
    if (!f) { ble_world_end(); return; }
    copy = *f;
    CHECK(ci_case(&C[1].t, &copy) == MT_OK);
    CHECK(invoke(&C[1].t, 0, GC, GC_COMPLETE, NULL, &r) == MT_OK && r.status == -1 && r.cmd == GC_COMPLETE_RESP &&
          r.f0 == 0);
    CHECK(mt_fabric_committed_count(&N->fabrics) == 1 && !BL.on && BL.window_off == 1);

    BL.window_on = BL.window_off = 0;
    reboot_node(0);
    CHECK(mt_fabric_committed_count(&N->fabrics) == 1 && !mt_node_window_open(N));
    settle(20 * 60 * 1000);                    /* past the 15 min BLE window and the boot window */
    CHECK(BL.window_on == 0 && BL.window_off == 0 && !BL.on && !mt_node_ble_on(N));
    /* a central that connects anyway (stale advertisement) is not served */
    BL.connected = true;
    ble_ev(MT_NODE_BLE_CONNECTED, mt_span_of(NULL, 0), 0);
    CHECK(BL.closes == 1 && BL.window_on == 0);
    ble_pump();
    ble_world_end();
}

static void test_ble(void)
{
    test_ble_commissioned_boot();
    test_ble_commissioning();
    test_ble_drop_keeps_failsafe();
    test_ble_link_rules();
    test_ble_window();
}
