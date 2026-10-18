/* Secure Channel protocol (0x0000) handler: PASE and CASE handshakes (one at a time), BUSY, CloseSession. */
#include "node_priv.h"

/* General status codes and Secure Channel protocol codes (spec 4.11.1.x, Appendix D). */
enum { GEN_SUCCESS = 0, GEN_FAILURE = 1, GEN_BUSY = 8 };
enum { SC_OK = 0, SC_NO_SHARED_TRUST_ROOTS = 1, SC_INVALID_PARAMETER = 2, SC_CLOSE_SESSION = 3, SC_BUSY = 4 };

/* Used exchanges / frame buffers. An unsecured conversation only starts while the reserve stays free, so
 * a flood of spoofed requests cannot take what secure sessions need. */
static bool starved(const mt_node *n)
{
    size_t xcs = 0, bufs = 0;
    for (size_t i = 0; i < MT_XCHG_N_EXCHANGES; i++) xcs += n->xchg.xc[i].used;
    for (size_t i = 0; i < MT_XCHG_N_TXBUF; i++) bufs += n->xchg.txbuf_used[i];
    return xcs + MT_NODE_XC_RESERVE > MT_XCHG_N_EXCHANGES || bufs + MT_NODE_TXBUF_RESERVE >= MT_XCHG_N_TXBUF;
}

/* A one-shot report: unreliable (no frame buffer or exchange slot is held), then the exchange is closed. */
static void report_and_close(mt_node *n, mt_xchg_xchg *xc, uint16_t general, uint16_t code, const uint8_t *extra,
                             size_t extra_len)
{
    uint8_t b[MT_PASE_STATUS_LEN + 2];
    size_t len = 0;
    if (mt_pase_status(general, code, mt_buf_of(b, sizeof b), &len) == MT_OK) {
        if (extra_len && len + extra_len <= sizeof b) { memcpy(b + len, extra, extra_len); len += extra_len; }
        (void)mt_xchg_send(&n->xchg, xc, MT_PASE_OP_STATUS, mt_span_of(b, len), false);
    }
    mt_xchg_close(&n->xchg, xc);
}

static void report_busy(mt_node *n, mt_xchg_xchg *xc)
{
    uint8_t wait[2];
    mt_put_le16(wait, MT_NODE_BUSY_WAIT_MS);
    report_and_close(n, xc, GEN_BUSY, SC_BUSY, wait, sizeof wait);
}

void node_attempt_end(mt_node *n, bool close_xc)
{
    mt_xchg_xchg *xc = n->att.xc;
    /* Pake2 went out and no session came of it: the initiator has tested one passcode guess. */
    bool failed_guess = n->att.kind == MT_SESS_PASE && n->att.guessed && n->att.u.pase.m.state != MT_PASE_ESTABLISHED;
    if (n->att.kind == MT_SESS_PASE) mt_pase_reset(&n->att.u.pase.m);
    else if (n->att.kind == MT_SESS_CASE) mt_case_reset(&n->att.u.cas);
    mt_wipe(&n->att, sizeof n->att);
    if (close_xc && xc) mt_xchg_close(&n->xchg, xc);
    if (failed_guess && ++n->failed_attempts >= MT_NODE_MAX_FAILED_ATTEMPTS) mt_node_set_window(n, false);
}

void node_sc_on_close(void *ctx, mt_xchg_xchg *xc, mt_xchg_end why)
{
    mt_node *n = ctx;
    (void)why;
    /* MRP gave up, idle timeout or the session went away. A handler-initiated close never gets here, and a
     * deferred one runs after node_attempt_end cleared att.xc, so a late END_MRP cannot hit a newer attempt. */
    if (n->att.kind && n->att.xc == xc) node_attempt_end(n, false);
}

/* A fresh local session ID: unused in the table and not the previous handshake's (spec 4.13.1.3 / 4.14.2.3). */
static bool alloc_session_id(mt_node *n, uint16_t *id)
{
    for (int i = 0; i < 4; i++) {
        if (mt_xchg_session_id_alloc(&n->xchg, id) != MT_OK) return false;
        if (*id != n->last_session_id) break;
    }
    n->last_session_id = *id;
    return true;
}

/* The handshake produced keys: add the session; the success report goes out on the unsecured exchange. */
static mt_err add_session(mt_node *n, mt_xchg_xchg *xc, mt_xchg_session_params *sp, const uint8_t *challenge,
                          const uint32_t *cats, uint8_t n_cats)
{
    mt_xchg_session *s = NULL;
    mt_node_sess *e;
    sp->transport = (mt_xchg_transport)xc->session->transport;   /* PASE over BLE stays on BTP */
    sp->addr = sp->transport == MT_XCHG_UDP ? &xc->session->addr : NULL;
    mt_err err = mt_xchg_session_add(&n->xchg, sp, &s);
    if (err != MT_OK || !s) return err ? err : MT_ERR_STATE;
    e = node_sess_of(n, s);
    mt_wipe(e, sizeof *e);
    e->local_id = s->local_id;
    memcpy(e->challenge, challenge, MT_ROOT_CHALLENGE_LEN);
    for (uint8_t i = 0; i < n_cats && i < MT_CERT_MAX_CATS; i++) e->cats[i] = cats[i];
    e->n_cats = n_cats;
    return MT_OK;
}

static void fail_and_end(mt_node *n, mt_xchg_xchg *xc, size_t len, uint8_t opcode)
{
    if (len) (void)mt_xchg_send(&n->xchg, xc, opcode, mt_span_of(n->sc_buf, len), false);
    node_attempt_end(n, true);
}

/* ---- PASE ---- */
static void pase_success(mt_node *n, mt_xchg_xchg *xc, const mt_pase_reply *rep)
{
    mt_pase_session ps;
    mt_xchg_session_params sp;
    mt_xchg_session *old[MT_XCHG_N_SESSIONS];
    size_t n_old = 0;
    uint16_t ps_local_id;
    mt_err e;

    if (mt_pase_session_keys(&n->att.u.pase.m, &ps) != MT_OK) { node_attempt_end(n, true); return; }
    ps_local_id = ps.local_session_id;
    /* One PASE session at most: the new one replaces any older one. */
    for (size_t i = 0; i < MT_XCHG_N_SESSIONS; i++)
        if (n->xchg.sess[i].kind == MT_SESS_PASE) old[n_old++] = &n->xchg.sess[i];
    for (size_t i = 0; i < n_old; i++) mt_xchg_session_close(&n->xchg, old[i], MT_XCHG_END_CLOSED);

    memset(&sp, 0, sizeof sp);
    sp.kind = MT_SESS_PASE;
    sp.local_id = ps.local_session_id;
    sp.peer_id = ps.peer_session_id;
    sp.idle_ms = ps.peer.idle_ms;
    sp.active_ms = ps.peer.active_ms;
    memcpy(sp.enc_key, ps.r2i, MT_CCM_KEY_LEN);
    memcpy(sp.dec_key, ps.i2r, MT_CCM_KEY_LEN);
    e = add_session(n, xc, &sp, ps.attestation_challenge, NULL, 0);
    mt_wipe(&ps, sizeof ps);
    mt_wipe(&sp, sizeof sp);
    if (e != MT_OK) { /* no room: tell the initiator it failed */
        report_and_close(n, xc, GEN_FAILURE, SC_INVALID_PARAMETER, NULL, 0);
        node_attempt_end(n, false);
        return;
    }
    /* The PASE session's implicit Administer is bounded by a fail-safe from the start: 60 s unless the
     * commissioner arms it itself (chip CommissioningWindowManager::OnSessionEstablished). */
    (void)mt_root_failsafe_arm(&n->root, 0, ps_local_id, MT_ROOT_PASE_FAILSAFE_S);
    /* Success report: reliable on the unsecured exchange; the exchange then lingers until acknowledged. */
    (void)mt_xchg_send(&n->xchg, xc, rep->opcode, mt_span_of(n->sc_buf, rep->len), true);
    node_attempt_end(n, true);
}

static void pase_feed(mt_node *n, mt_xchg_xchg *xc, const mt_proto_hdr *h, mt_span payload)
{
    mt_pase_reply rep;
    memset(&rep, 0, sizeof rep);
    n->att.last_rx = node_now(n);
    mt_err e = mt_pase_recv(&n->att.u.pase.m, h->opcode, payload, mt_buf_of(n->sc_buf, sizeof n->sc_buf), &rep);
    if (n->att.u.pase.m.state == MT_PASE_WAIT_PAKE3) n->att.guessed = true; /* before any send: counts even if it fails */
    if (e != MT_OK) { fail_and_end(n, xc, rep.len, rep.opcode); return; }
    if (n->att.u.pase.m.state == MT_PASE_ESTABLISHED) { pase_success(n, xc, &rep); return; }
    if (rep.len == 0 || mt_xchg_send(&n->xchg, xc, rep.opcode, mt_span_of(n->sc_buf, rep.len), true) != MT_OK)
        node_attempt_end(n, true);
}

static bool pase_begin(mt_node *n, mt_xchg_xchg *xc)
{
    mt_node_attempt *a = &n->att;
    uint16_t id = 0;
    mt_wipe(a, sizeof *a);
    if (!node_window_verifier(n, &a->u.pase.cfg) || !alloc_session_id(n, &id)) { mt_wipe(a, sizeof *a); return false; }
    a->kind = MT_SESS_PASE;
    a->xc = xc;
    a->deadline = node_now(n) + MT_NODE_ATTEMPT_MS;
    a->u.pase.cfg.session_id = id;
    a->u.pase.cfg.params.idle_ms = n->mrp_idle_ms;
    a->u.pase.cfg.params.active_ms = n->mrp_active_ms;
    a->u.pase.cfg.params.active_threshold_ms = MT_XCHG_ACTIVE_THRESHOLD_MS;
    a->u.pase.cfg.params.data_model_revision = MT_BASIC_DATA_MODEL_REV;
    a->u.pase.cfg.params.im_revision = MT_IM_REVISION;
    a->u.pase.cfg.params.specification_version = MT_BASIC_SPEC_VERSION;
    a->u.pase.cfg.params.max_paths_per_invoke = 1;
    mt_pase_init(&a->u.pase.m, &a->u.pase.cfg, &n->rng);
    return true;
}

/* ---- CASE ---- */
static void case_success(mt_node *n, mt_xchg_xchg *xc, const mt_case_reply *rep)
{
    mt_case_session cs;
    mt_xchg_session_params sp;
    mt_err e;
    if (mt_case_session_keys(&n->att.u.cas, &cs) != MT_OK) { node_attempt_end(n, true); return; }
    memset(&sp, 0, sizeof sp);
    sp.kind = MT_SESS_CASE;
    sp.fabric_index = cs.fabric_index;
    sp.local_id = cs.local_session_id;
    sp.peer_id = cs.peer_session_id;
    sp.peer_node = cs.peer_node_id;
    sp.local_node = cs.local_node_id;        /* our operational node ID: the nonce source of our frames */
    sp.idle_ms = cs.peer.idle_ms;
    sp.active_ms = cs.peer.active_ms;
    memcpy(sp.enc_key, cs.r2i, MT_CCM_KEY_LEN);
    memcpy(sp.dec_key, cs.i2r, MT_CCM_KEY_LEN);
    e = add_session(n, xc, &sp, cs.attestation_challenge, cs.peer_cats, cs.n_peer_cats);
    mt_wipe(&cs, sizeof cs);
    mt_wipe(&sp, sizeof sp);
    if (e != MT_OK) {
        report_and_close(n, xc, GEN_FAILURE, SC_INVALID_PARAMETER, NULL, 0);
        node_attempt_end(n, false);
        return;
    }
    (void)mt_xchg_send(&n->xchg, xc, rep->opcode, mt_span_of(n->sc_buf, rep->len), true);
    node_attempt_end(n, true);
}

static void case_feed(mt_node *n, mt_xchg_xchg *xc, const mt_proto_hdr *h, mt_span payload)
{
    mt_case_reply rep;
    memset(&rep, 0, sizeof rep);
    n->att.last_rx = node_now(n);
    mt_err e = mt_case_recv(&n->att.u.cas, h->opcode, payload, mt_buf_of(n->sc_buf, sizeof n->sc_buf),
                            mt_buf_of(n->work, sizeof n->work), &rep);
    if (e != MT_OK) {
        n->case_failed++;
        fail_and_end(n, xc, rep.len, rep.opcode);
        return;
    }
    if (n->att.u.cas.state == MT_CASE_ESTABLISHED) { case_success(n, xc, &rep); return; }
    if (rep.len == 0 || mt_xchg_send(&n->xchg, xc, rep.opcode, mt_span_of(n->sc_buf, rep.len), true) != MT_OK)
        node_attempt_end(n, true);
}

static bool case_begin(mt_node *n, mt_xchg_xchg *xc)
{
    mt_node_attempt *a = &n->att;
    uint16_t id = 0;
    mt_wipe(a, sizeof *a);
    if (!alloc_session_id(n, &id)) return false;
    a->kind = MT_SESS_CASE;
    a->xc = xc;
    a->deadline = node_now(n) + MT_NODE_ATTEMPT_MS;
    /* Certificate validity is checked against the node's UTC time once it has one (SetUTCTime, SNTP); 0 skips it. */
    mt_case_init(&a->u.cas, &n->case_cfg, &n->rng, id, mt_root_utc_now(&n->root));
    return true;
}

/* ---- dispatch ---- */
static void start_handshake(mt_node *n, mt_xchg_xchg *xc, const mt_proto_hdr *h, mt_span payload, uint8_t kind)
{
    if (starved(n)) { n->sc_refused++; mt_xchg_close(&n->xchg, xc); return; }
    if (n->att.kind) {
        if (n->att.xc == xc) { node_attempt_end(n, true); return; } /* a repeated request: protocol error */
        if (!mt_due(node_now(n), n->att.last_rx + MT_NODE_STALL_MS)) {
            n->sc_refused++;
            report_busy(n, xc);
            return;
        }
        node_attempt_end(n, true); /* the initiator went quiet: the slot goes to the new request */
        if (starved(n)) { n->sc_refused++; mt_xchg_close(&n->xchg, xc); return; }
    }
    if (kind == MT_SESS_CASE) n->case_started++;
    if (kind == MT_SESS_PASE ? !pase_begin(n, xc) : !case_begin(n, xc)) { mt_xchg_close(&n->xchg, xc); return; }
    if (kind == MT_SESS_PASE) pase_feed(n, xc, h, payload);
    else case_feed(n, xc, h, payload);
}

static void unsecured_msg(mt_node *n, mt_xchg_xchg *xc, const mt_proto_hdr *h, mt_span payload)
{
    switch (h->opcode) {
    case MT_PASE_OP_PARAM_REQ:
        if (!mt_node_window_open(n)) { mt_xchg_close(&n->xchg, xc); return; }
        start_handshake(n, xc, h, payload, MT_SESS_PASE);
        return;
    case MT_CASE_OP_SIGMA1:
        start_handshake(n, xc, h, payload, MT_SESS_CASE);
        return;
    case MT_PASE_OP_PAKE1:
    case MT_PASE_OP_PAKE3:
        if (n->att.kind != MT_SESS_PASE || n->att.xc != xc) { mt_xchg_close(&n->xchg, xc); return; }
        pase_feed(n, xc, h, payload);
        return;
    case MT_CASE_OP_SIGMA3:
        if (n->att.kind != MT_SESS_CASE || n->att.xc != xc) { mt_xchg_close(&n->xchg, xc); return; }
        case_feed(n, xc, h, payload);
        return;
    case MT_PASE_OP_STATUS:
        if (!n->att.kind || n->att.xc != xc) { mt_xchg_close(&n->xchg, xc); return; }
        if (n->att.kind == MT_SESS_PASE) pase_feed(n, xc, h, payload);
        else case_feed(n, xc, h, payload);
        return;
    default:
        mt_xchg_close(&n->xchg, xc);
        return;
    }
}

static void secure_msg(mt_node *n, mt_xchg_xchg *xc, const mt_proto_hdr *h, mt_span payload)
{
    mt_xchg_session *s = xc->session;
    /* CloseSession: StatusReport {general SUCCESS, protocol Secure Channel, code CloseSession}. */
    bool close_session = h->opcode == MT_PASE_OP_STATUS && payload.len >= MT_PASE_STATUS_LEN &&
                         mt_get_le16(payload.p) == GEN_SUCCESS && mt_get_le32(payload.p + 2) == 0 &&
                         mt_get_le16(payload.p + 6) == SC_CLOSE_SESSION;
    mt_xchg_close(&n->xchg, xc); /* flushes the ack for the request */
    if (close_session) mt_xchg_session_close(&n->xchg, s, MT_XCHG_END_CLOSED);
}

void node_sc_on_msg(void *ctx, mt_xchg_xchg *xc, const mt_proto_hdr *h, mt_span payload)
{
    mt_node *n = ctx;
    if (xc->session->kind == MT_SESS_UNSECURED) unsecured_msg(n, xc, h, payload);
    else secure_msg(n, xc, h, payload);
}
