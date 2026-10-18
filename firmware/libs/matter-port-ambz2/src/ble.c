/* BLE commissioning glue: matter-node's BLE ports over btp-port-ambz2, and its events into the node (Matter task).
 * The node asks for BLE while a BASIC window wants it; BLE off is one-way (Realtek's deinit leaks ~2.4 KiB), so a
 * later window (the last fabric removed) reboots the device, which then starts uncommissioned with BLE. */
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "btp_port.h"
#include "port.h"
#include "sys_api.h"

#define REBOOT_DELAY_MS 3000u   /* lets the RemoveFabric response and its ack go out */

static btpp_cfg cfg;
static bool reboot_pending;
static TickType_t reboot_at;

static void notify(void) { mtp_wake(); }   /* BLE task: the Matter task drains the events on its next loop */

void mtp_ble_init(const mtp_credentials *c)
{
    cfg.discriminator = c->discriminator;
    cfg.vendor_id = c->vendor_id;
    cfg.product_id = c->product_id;
    cfg.notify = notify;
}

bool mtp_ble_send(void *ctx, mt_span pkt)
{
    (void)ctx;
    return btpp_send(pkt.p, pkt.len);
}

void mtp_ble_close(void *ctx)
{
    (void)ctx;
    btpp_disconnect();
}

void mtp_ble_window(void *ctx, bool open)
{
    (void)ctx;
    if (!open) {
        if (!btpp_stop()) {     /* the radio may still be on: no flash write (not even the kv flush), reboot now */
            MTP_LOG("ble: stop timed out, rebooting\r\n");
            sys_reset();
        }
        mtp_netctl_ble_closed();   /* radio off: the commit's flash writes may follow */
        return;
    }
    switch (btpp_get_state()) {
    case BTPP_OFF:
        mtp_netctl_ble_opened();
        if (btpp_start(&cfg)) btpp_advertise(true);
        else mtp_netctl_ble_closed();   /* BLE won't come up: the rescue network stays reachable */
        break;
    case BTPP_STARTING:
    case BTPP_READY:
        btpp_advertise(true);
        break;
    case BTPP_STOPPED:
        if (!reboot_pending) {
            MTP_LOG("ble: a new commissioning window needs BLE again: rebooting\r\n");
            reboot_pending = true;
            reboot_at = xTaskGetTickCount() + pdMS_TO_TICKS(REBOOT_DELAY_MS);
        }
        break;
    case BTPP_FAILED:
        break;
    }
}

/* One line per GATT event, so a failed BLE commissioning can be read back from the netlog once Wi-Fi is up.
 * Writes show the first BTP header bytes only. Disconnects show why the node dropped the link, if it did. */
static void log_event(const mt_node *n, const btpp_event *ev)
{
    static const char *const name[] = {
        [BTPP_EV_CONNECTED] = "conn", [BTPP_EV_MTU] = "mtu",     [BTPP_EV_SUBSCRIBED] = "sub",
        [BTPP_EV_UNSUBSCRIBED] = "unsub", [BTPP_EV_WRITE] = "wr", [BTPP_EV_SENT] = "sent",
        [BTPP_EV_DISCONNECTED] = "disc",
    };
    unsigned ms = (unsigned)(xTaskGetTickCount() * portTICK_PERIOD_MS);
    if (ev->kind == BTPP_EV_WRITE)
        MTP_LOG("ble ev %u wr len %u %02x %02x %02x %02x\r\n", ms, ev->len, ev->len > 0 ? ev->data[0] : 0,
                ev->len > 1 ? ev->data[1] : 0, ev->len > 2 ? ev->data[2] : 0, ev->len > 3 ? ev->data[3] : 0);
    else if (ev->kind == BTPP_EV_DISCONNECTED)
        MTP_LOG("ble ev %u disc 0x%x node why %u\r\n", ms, ev->val, (unsigned)mt_node_ble_close_why(n));
    else
        MTP_LOG("ble ev %u %s %u\r\n", ms, name[ev->kind], ev->val);
}

void mtp_ble_drain(mt_node *n)
{
    static btpp_event ev;
    static const mt_node_ble_ev map[] = {
        [BTPP_EV_CONNECTED] = MT_NODE_BLE_CONNECTED,     [BTPP_EV_MTU] = MT_NODE_BLE_MTU,
        [BTPP_EV_SUBSCRIBED] = MT_NODE_BLE_SUBSCRIBED,   [BTPP_EV_UNSUBSCRIBED] = MT_NODE_BLE_UNSUBSCRIBED,
        [BTPP_EV_WRITE] = MT_NODE_BLE_WRITE,             [BTPP_EV_SENT] = MT_NODE_BLE_SENT,
        [BTPP_EV_DISCONNECTED] = MT_NODE_BLE_DISCONNECTED,
    };
    while (btpp_next(&ev)) {
        if (ev.kind >= sizeof map / sizeof map[0]) continue;
        log_event(n, &ev);
        mt_node_on_ble(n, map[ev.kind], mt_span_of(ev.data, ev.len), ev.val);
    }
}

uint32_t mtp_ble_poll(mtp_kv *kv)
{
    static bool failed_seen;
    int32_t left;
    if (!failed_seen && btpp_get_state() == BTPP_FAILED) {   /* no BLE commissioning after all: Wi-Fi rescue */
        failed_seen = true;
        mtp_netctl_ble_closed();
    }
    if (!reboot_pending) return btpp_get_state() == BTPP_STARTING ? 1000u : UINT32_MAX;   /* watch for FAILED */
    left = (int32_t)(reboot_at - xTaskGetTickCount());
    if (left > 0) return (uint32_t)left;
    if (mtp_kv_flush(kv) != MT_OK) MTP_LOG("ble: deferred kv write failed before the reboot\r\n");
    sys_reset();
    return UINT32_MAX;
}

bool mtp_ble_settled(void) { return btpp_get_state() != BTPP_STARTING; }
