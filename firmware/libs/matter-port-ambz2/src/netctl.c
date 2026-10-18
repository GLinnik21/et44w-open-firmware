/* Network Commissioning's netctl over wifi-sta (runtime credentials) and wifi_conf, plus the WIFI record:
 * one network, stored as [ssid len][ssid][cred len][creds] in the node module.
 *
 * connect: wifi_sta_set_credentials switches the station; the result is matched by credential generation: the
 * first IPv4 address (onIP) of that generation is MT_NET_OK, its first connect failure a MT_NET_* error, and no
 * answer within CONNECT_TIMEOUT_MS is OTHER_CONNECTION_FAILURE. wifi-sta keeps retrying afterwards; the fail-safe
 * (revert) or a new connect decides what happens next. The security type: open exactly when the credentials are
 * empty (a same-SSID open AP never downgrades a passphrase network), WPA3 / mixed when the last scan saw the SSID
 * with it, else WPA2-AES-PSK (wifi_sec_policy.h).
 * scan: wifi_scan_networks; the RTW callback keeps the MAX_APS strongest matches, the result is posted to the
 * Matter task. */
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "lwip/netif.h"
#include "lwip_netconf.h"
#include "wifi_conf.h"

#include "wifi_sta.h"

#include "port.h"
#include "rescue_policy.h"
#include "wifi_sec_policy.h"

#define MAX_APS 10
#define CONNECT_TIMEOUT_MS 45000u   /* wifi_connect alone can block ~20 s, then DHCP up to 15 s */
#define WIFI_REC_MAX (2 + MT_NETCTL_SSID_MAX + MT_NETCTL_CRED_MAX)

_Static_assert(MT_NETCTL_SSID_MAX == WIFI_STA_SSID_MAX && MT_NETCTL_CRED_MAX == WIFI_STA_PASS_MAX, "limits");

typedef struct {
    uint8_t ssid_len, cred_len;
    uint8_t ssid[MT_NETCTL_SSID_MAX];
    uint8_t cred[MT_NETCTL_CRED_MAX];
} net;

static const mtp_app *app;
static net saved_net, boot_net;              /* stored record; what the station started with */
static bool have_saved, have_boot;
static bool rescue_mode, rescue_on, ble_open, ble_closed;   /* app->dev_rescue: boot_net only as a fallback */
static uint32_t rescue_drop_at;                              /* ble_open: leave the rescue network then */
#define RESCUE_DROP_GRACE_MS 3000u
static volatile uint32_t pending_gen;        /* connect in progress (0 = none) */
static uint32_t pending_deadline;
static net pending_net;                     /* its network (for the failure status) */

/* scan: `found` is filled in the RTW thread while `scanning`, `results` belongs to the Matter task */
static volatile bool scanning;
static mt_netctl_ap found[MAX_APS], results[MAX_APS];
static uint8_t n_found, n_results;
static uint8_t scan_ssid[MT_NETCTL_SSID_MAX], scan_ssid_len;

/* ---- WIFI record ---- */

static bool rec_load(net *out)
{
    uint8_t b[WIFI_REC_MAX];
    size_t len = 0;
    if (mtp_store_get(MTP_MOD_NODE, MTP_NAME_WIFI, mt_buf_of(b, sizeof b), &len) != MT_OK || len < 2) return false;
    out->ssid_len = b[0];
    if (out->ssid_len == 0 || out->ssid_len > MT_NETCTL_SSID_MAX || len < 2u + out->ssid_len) return false;
    out->cred_len = b[1 + out->ssid_len];
    if (out->cred_len > MT_NETCTL_CRED_MAX || len != 2u + out->ssid_len + out->cred_len) return false;
    memcpy(out->ssid, b + 1, out->ssid_len);
    memcpy(out->cred, b + 2 + out->ssid_len, out->cred_len);
    return true;
}

static bool net_set(net *n, mt_span ssid, mt_span cred)
{
    if (ssid.len == 0 || ssid.len > MT_NETCTL_SSID_MAX || cred.len > MT_NETCTL_CRED_MAX) return false;
    memset(n, 0, sizeof *n);
    n->ssid_len = (uint8_t)ssid.len;
    n->cred_len = (uint8_t)cred.len;
    memcpy(n->ssid, ssid.p, ssid.len);
    if (cred.len) memcpy(n->cred, cred.p, cred.len);
    return true;
}

/* ---- security ---- */

static uint8_t sec_bits(rtw_security_t s)
{
    uint32_t v = (uint32_t)s;
    uint8_t b = 0;
    if (s == RTW_SECURITY_OPEN) return MT_WIFI_SEC_UNENCRYPTED;
    if (v & WPA3_SECURITY) b |= MT_WIFI_SEC_WPA3;
    if (v & WPA2_SECURITY) b |= MT_WIFI_SEC_WPA2;
    if (v & WPA_SECURITY) b |= MT_WIFI_SEC_WPA;
    if (!b && (v & WEP_ENABLED)) b |= MT_WIFI_SEC_WEP;
    return b;
}

static int32_t sec_for(const net *n)
{
    switch (mtp_sec_pick(results, n_results, n->ssid, n->ssid_len, n->cred_len != 0)) {
    case MTP_SEC_WPA3: return RTW_SECURITY_WPA3_AES_PSK;
    case MTP_SEC_WPA2_WPA3: return RTW_SECURITY_WPA2_WPA3_MIXED;
    default: return WIFI_STA_SEC_AUTO;
    }
}

static uint32_t use(const net *n)
{
    return wifi_sta_set_credentials(n->ssid, n->ssid_len, n->cred, n->cred_len, sec_for(n));
}

/* ---- wifi-sta callbacks (Wi-Fi task) ---- */

static void on_ip(void)
{
    mtp_post(&(const mtp_event){ .kind = MTP_EV_IP, .gen = wifi_sta_generation() });
    if (app->on_ip) app->on_ip(app->ctx);
}

static void on_down(wifi_sta_down why, uint32_t gen)
{
    uint8_t st = why == WIFI_STA_DOWN_CONNECT_FAILED ? MT_NET_AUTH_FAILURE   /* refined in the Matter task */
               : why == WIFI_STA_DOWN_NO_DHCP ? MT_NET_IP_BIND_FAILED : MT_NET_OTHER_CONNECTION_FAILURE;
    if (gen == pending_gen) mtp_post(&(const mtp_event){ .kind = MTP_EV_CONNECT, .status = st, .gen = gen });
}

static const wifi_sta_config sta_cfg = { .ssid = NULL, .password = NULL, .onIP = on_ip };

static bool net_same(const net *a, const net *b)
{
    return a->ssid_len == b->ssid_len && a->cred_len == b->cred_len && !memcmp(a->ssid, b->ssid, a->ssid_len) &&
           !memcmp(a->cred, b->cred, a->cred_len);
}

void mtp_netctl_start(const mtp_app *a)
{
    app = a;
    wifi_sta_set_on_down(on_down);
    if (a->dev_ssid && a->dev_pass)
        have_boot = net_set(&boot_net, mt_span_of(a->dev_ssid, strlen(a->dev_ssid)),
                            mt_span_of(a->dev_pass, strlen(a->dev_pass)));
    rescue_mode = have_boot && a->dev_rescue;
    MTP_LOG("wifi: %s\r\n", rescue_mode ? "off until the store is read (development network only as a rescue)"
                             : have_boot ? "development network until the store is read" : "none until the store is read");
    if (have_boot && !rescue_mode) use(&boot_net);
    wifi_sta_start(&sta_cfg);
}

void mtp_netctl_load(void)
{
    have_saved = rec_load(&saved_net);
    if (!have_saved) {
        MTP_LOG("wifi: no stored network, %s\r\n", rescue_mode ? "waiting for commissioning"
                                                  : have_boot ? "staying on the development network" : "none (BLE only)");
        return;
    }
    if (have_boot && !rescue_mode && net_same(&saved_net, &boot_net)) {
        MTP_LOG("wifi: stored network = development network\r\n");
        return;
    }
    MTP_LOG("wifi: switching to the stored network\r\n");
    use(&saved_net);
}

void mtp_netctl_rescue(const char *why)
{
    if (!rescue_mode || rescue_on || have_saved) return;
    rescue_on = true;
    MTP_LOG("wifi: %s: joining the development network (rescue)\r\n", why);
    use(&boot_net);
}

void mtp_netctl_ble_opened(void)
{
    ble_open = true;
    ble_closed = false;
    rescue_drop_at = mtp_now_ms(NULL) + RESCUE_DROP_GRACE_MS;
}

void mtp_netctl_ble_closed(void)
{
    ble_open = false;
    ble_closed = true;
}

bool mtp_offline_for_ble(void)
{
    return rescue_mode && !have_saved && ble_open && !rescue_on;
}

/* ---- netctl ops (Matter task) ---- */

static bool op_saved(void *ctx, uint8_t ssid[MT_NETCTL_SSID_MAX], size_t *len)
{
    (void)ctx;
    if (!have_saved) return false;
    memcpy(ssid, saved_net.ssid, saved_net.ssid_len);
    *len = saved_net.ssid_len;
    return true;
}

static mt_err rec_store(const net *n)
{
    uint8_t b[WIFI_REC_MAX];
    mt_err e;
    b[0] = n->ssid_len;
    memcpy(b + 1, n->ssid, n->ssid_len);
    b[1 + n->ssid_len] = n->cred_len;
    memcpy(b + 2 + n->ssid_len, n->cred, n->cred_len);
    e = mtp_store_set(MTP_MOD_NODE, MTP_NAME_WIFI, mt_span_of(b, 2u + n->ssid_len + n->cred_len)) ? MT_ERR_IO : MT_OK;
    mt_wipe(b, sizeof b);
    return e;
}

/* The record before the last save / erase, for op_restore (a CommissioningComplete whose fabric commit failed). */
static net prev_net;
static bool have_prev, prev_saved;

static void keep_prev(void)
{
    prev_net = saved_net;
    prev_saved = have_saved;
    have_prev = true;
}

static mt_err op_save(void *ctx, mt_span ssid, mt_span creds)
{
    net n;
    (void)ctx;
    if (!net_set(&n, ssid, creds)) return MT_ERR_INVALID;
    if (rec_store(&n)) return MT_ERR_IO;
    keep_prev();
    saved_net = n;
    have_saved = true;
    return MT_OK;
}

static mt_err op_erase(void *ctx)
{
    (void)ctx;
    if (mtp_store_del(MTP_MOD_NODE, MTP_NAME_WIFI)) return MT_ERR_IO;
    keep_prev();
    have_saved = false;
    return MT_OK;
}

static mt_err op_restore(void *ctx)
{
    mt_err e;
    (void)ctx;
    if (!have_prev) return MT_OK;
    e = prev_saved ? rec_store(&prev_net) : (mtp_store_del(MTP_MOD_NODE, MTP_NAME_WIFI) ? MT_ERR_IO : MT_OK);
    if (e) {
        MTP_LOG("wifi: restoring the previous network record failed\r\n");
        return e;
    }
    saved_net = prev_net;
    have_saved = prev_saved;
    have_prev = false;
    mt_wipe(&prev_net, sizeof prev_net);
    return MT_OK;
}

mt_err mtp_netctl_forget(void) { return op_erase(NULL); }

static bool current(rtw_wifi_setting_t *s)
{
    if (wifi_is_connected_to_ap() != RTW_SUCCESS) return false;
    memset(s, 0, sizeof *s);
    return wifi_get_setting(WLAN0_NAME, s) == 0 && s->ssid[0];
}

static bool op_connected(void *ctx, uint8_t ssid[MT_NETCTL_SSID_MAX], size_t *len)
{
    rtw_wifi_setting_t s;
    size_t n;
    (void)ctx;
    if (!current(&s)) return false;
    n = strnlen((const char *)s.ssid, MT_NETCTL_SSID_MAX);
    memcpy(ssid, s.ssid, n);
    *len = n;
    return true;
}

static bool op_is_current(void *ctx, mt_span ssid, mt_span creds)
{
    rtw_wifi_setting_t s;
    (void)ctx;
    if (!current(&s)) return false;
    return strnlen((const char *)s.ssid, sizeof s.ssid) == ssid.len && !memcmp(s.ssid, ssid.p, ssid.len) &&
           strnlen((const char *)s.password, sizeof s.password) == creds.len &&
           (!creds.len || !memcmp(s.password, creds.p, creds.len));
}

static mt_err op_connect(void *ctx, mt_span ssid, const mt_span *creds)
{
    net n;
    uint32_t gen;
    (void)ctx;
    if (creds) {
        if (!net_set(&n, ssid, *creds)) return MT_ERR_INVALID;
    } else {
        if (!have_saved || ssid.len != saved_net.ssid_len || memcmp(ssid.p, saved_net.ssid, ssid.len))
            return MT_ERR_NOT_FOUND;
        n = saved_net;
    }
    pending_gen = 0;   /* results of an older connect no longer count */
    gen = use(&n);
    if (!gen) return MT_ERR_INVALID;
    pending_net = n;
    pending_deadline = mtp_now_ms(NULL) + CONNECT_TIMEOUT_MS;
    pending_gen = gen;
    return MT_OK;
}

static void op_revert(void *ctx)
{
    (void)ctx;
    pending_gen = 0;
    if (have_saved) use(&saved_net);
    else if (have_boot && (!rescue_mode || rescue_on)) use(&boot_net);
    else wifi_sta_set_credentials(NULL, 0, NULL, 0, WIFI_STA_SEC_AUTO);
}

static rtw_result_t scan_cb(rtw_scan_handler_result_t *r)
{
    if (!scanning) return RTW_SUCCESS;
    if (!r->scan_complete) {
        const rtw_scan_result_t *d = &r->ap_details;
        mt_netctl_ap ap;
        unsigned at;
        uint8_t len = d->SSID.len > MT_NETCTL_SSID_MAX ? MT_NETCTL_SSID_MAX : d->SSID.len;
        if (scan_ssid_len && (len != scan_ssid_len || memcmp(d->SSID.val, scan_ssid, len))) return RTW_SUCCESS;
        memset(&ap, 0, sizeof ap);
        ap.security = sec_bits(d->security);
        memcpy(ap.ssid, d->SSID.val, len);
        ap.ssid_len = len;
        memcpy(ap.bssid, d->BSSID.octet, 6);
        ap.channel = (uint16_t)d->channel;
        ap.band = d->band == RTW_802_11_BAND_5GHZ ? MT_WIFI_BAND_5G : MT_WIFI_BAND_2G4;
        ap.rssi = (int8_t)(d->signal_strength < -128 ? -128 : d->signal_strength > 0 ? 0 : d->signal_strength);
        /* keep the strongest MAX_APS, sorted by RSSI */
        for (at = n_found; at > 0 && found[at - 1].rssi < ap.rssi; at--) {}
        if (at >= MAX_APS) return RTW_SUCCESS;
        if (n_found < MAX_APS) n_found++;
        memmove(&found[at + 1], &found[at], (n_found - 1 - at) * sizeof found[0]);
        found[at] = ap;
        return RTW_SUCCESS;
    }
    scanning = false;
    mtp_post(&(const mtp_event){ .kind = MTP_EV_SCAN, .status = MT_NET_OK });
    return RTW_SUCCESS;
}

static mt_err op_scan(void *ctx, mt_span ssid)
{
    (void)ctx;
    if (scanning) return MT_ERR_STATE;
    if (ssid.len > MT_NETCTL_SSID_MAX) return MT_ERR_INVALID;
    memcpy(scan_ssid, ssid.p, ssid.len);
    scan_ssid_len = (uint8_t)ssid.len;
    n_found = 0;
    scanning = true;
    if (wifi_scan_networks(scan_cb, NULL) != RTW_SUCCESS) {
        scanning = false;
        return MT_ERR_IO;
    }
    return MT_OK;
}

static bool op_scan_result(void *ctx, uint16_t idx, mt_netctl_ap *out)
{
    (void)ctx;
    if (idx >= n_results) return false;
    *out = results[idx];
    return true;
}

static const mt_netctl_ops ops = {
    .saved = op_saved, .save = op_save, .erase = op_erase, .connected = op_connected,
    .is_current = op_is_current, .connect = op_connect, .revert = op_revert, .scan = op_scan,
    .scan_result = op_scan_result, .set_enabled = NULL, .restore = op_restore,
};

const mt_netctl_ops *mtp_netctl_ops(void) { return &ops; }

static bool in_results(const net *n)
{
    for (unsigned i = 0; i < n_results; i++)
        if (results[i].ssid_len == n->ssid_len && !memcmp(results[i].ssid, n->ssid, n->ssid_len)) return true;
    return false;
}

/* wifi_connect failed: a network the last scan saw means rejected credentials, one it didn't see is missing;
 * without a scan the cause is unknown. */
static uint8_t refine(uint8_t status)
{
    if (status != MT_NET_AUTH_FAILURE) return status;
    if (!n_results) return MT_NET_OTHER_CONNECTION_FAILURE;
    return in_results(&pending_net) ? MT_NET_AUTH_FAILURE : MT_NET_NETWORK_NOT_FOUND;
}

void mtp_netctl_event(mt_node *n, const mtp_event *e)
{
    switch (e->kind) {
    case MTP_EV_SCAN:
        memcpy(results, found, sizeof results);   /* the RTW thread is done with `found` */
        n_results = n_found;
        mt_node_net_scan_done(n, e->status);
        break;
    case MTP_EV_IP:
        mtp_mdns_restart();
        mt_gendiag_iface_changed(&n->gendiag, &n->dm);
        if (pending_gen && e->gen == pending_gen) {
            pending_gen = 0;
            mt_node_net_connect_done(n, MT_NET_OK, NULL);
        }
        break;
    case MTP_EV_CONNECT:
        if (pending_gen && e->gen == pending_gen) {
            int32_t err = e->status;
            pending_gen = 0;
            mt_node_net_connect_done(n, refine(e->status), &err);
        }
        break;
    default:
        break;
    }
}

uint32_t mtp_netctl_poll(mt_node *n)
{
    int32_t left;
    const mtp_rescue_state rs = { .mode = rescue_mode, .on = rescue_on, .saved = have_saved, .pending = pending_gen != 0,
                                  .failsafe = mt_node_failsafe_armed(n), .ble_open = ble_open,
                                  .ble_closed = ble_closed, .window_open = mt_node_window_open(n) };
    if (mtp_rescue_leave(&rs)) {
        left = (int32_t)(rescue_drop_at - mtp_now_ms(NULL));
        if (left > 0) return (uint32_t)left;
        rescue_on = false;
        MTP_LOG("wifi: BLE commissioning: leaving the development network\r\n");
        wifi_sta_set_credentials(NULL, 0, NULL, 0, WIFI_STA_SEC_AUTO);
    } else if (mtp_rescue_join(&rs)) {
        mtp_netctl_rescue(ble_closed ? "BLE window closed without a network" : "commissioned without a stored network");
    }
    if (!pending_gen) return UINT32_MAX;
    left = (int32_t)(pending_deadline - mtp_now_ms(NULL));
    if (left > 0) return (uint32_t)left;
    pending_gen = 0;
    mt_node_net_connect_done(n, MT_NET_OTHER_CONNECTION_FAILURE, NULL);
    return UINT32_MAX;
}

/* ---- General Diagnostics NetworkInterfaces ---- */

bool mtp_iface(void *ctx, mt_gendiag_iface *out)
{
    struct netif *nif = &xnetif[0];
    const uint8_t *ip4 = LwIP_GetIP(nif);
    (void)ctx;
    memset(out, 0, sizeof *out);
    strcpy(out->name, "wlan0");
    out->type = MT_IFACE_WIFI;
    memcpy(out->hw, nif->hwaddr, 6);
    out->hw_len = 6;
    out->operational = wifi_is_connected_to_ap() == RTW_SUCCESS && (ip4[0] | ip4[1] | ip4[2] | ip4[3]);
    if (ip4[0] | ip4[1] | ip4[2] | ip4[3]) {
        memcpy(out->v4[0], ip4, 4);
        out->n4 = 1;
    }
#if LWIP_IPV6
    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES && out->n6 < MT_GENDIAG_MAX_V6; i++) {
        if (!ip6_addr_isvalid(netif_ip6_addr_state(nif, i))) continue;
        memcpy(out->v6[out->n6++], netif_ip6_addr(nif, i)->addr, 16);
    }
#endif
    return true;
}
