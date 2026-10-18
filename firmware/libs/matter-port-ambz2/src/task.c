/* The Matter task: owns the node (the stack is single threaded: only this task calls into it) and everything that
 * calls into it.
 *
 * Start: mtp_start (main) starts Wi-Fi on the development network before the scheduler. The task then waits
 * MTP_WDOG_HOLD_MS after a watchdog reset, opens the store (DCT2) -> boot bookkeeping / safe mode -> switches Wi-Fi
 * to the stored network, if any -> loads the node's records -> UDP -> mt_node_init. The fault counter is updated
 * before the records are parsed, so a crash loop while loading them still ends in safe mode.
 * Loop: wait on the event queue for at most the time the node, the app and the port's timers allow; handle one
 * event (RX datagram, Wi-Fi connect / scan result, IP change, app call, BLE wake); feed pending BLE events to the
 * node; then poll. Node-level records the node
 * stages during a PASE/CASE handshake are written once it is idle (store_kv deferral).
 *
 * Stack 8 KiB (CASE / PASE crypto runs here; its peak stack use was measured on the host). Priority tskIDLE + 1,
 * the same as the watchdog feeder, OTA and netlog: round-robin with them, so a 1-2 s CASE computation cannot
 * starve the feeder and the HAP-era recovery paths stay responsive. */
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "queue.h"
#include "task.h"

#include "boot_policy.h"
#include "port.h"
#include "sys_api.h"

#define TASK_STACK_WORDS 2048
#define TASK_PRIORITY (tskIDLE_PRIORITY + 1)
#define QUEUE_LEN 8
#define FLUSH_RETRY_MS 1000u

static const mtp_app *app;
static QueueHandle_t queue;
static mt_node node;
static volatile bool running;

bool mtp_post(const mtp_event *e) { return queue && xQueueSend(queue, e, 0) == pdTRUE; }

bool mtp_call(void (*fn)(mt_node *n, void *arg), void *arg)
{
    return running && fn && mtp_post(&(const mtp_event){ .kind = MTP_EV_CALL, .fn = fn, .arg = arg });
}

void mtp_wake(void) { (void)mtp_post(&(const mtp_event){ .kind = MTP_EV_WAKE }); }

bool mtp_running(void) { return running; }

/* No flash writes during a handshake or while a BLE link is up (a flash write stalls the radio's timing). */
static bool kv_busy(void *ctx) { return mt_node_handshake_busy(ctx) || mt_node_ble_connected(ctx); }


static void handle(const mtp_event *e)
{
    switch (e->kind) {
    case MTP_EV_RX: {
        mtp_rx_slot *s = mtp_udp_slot(e->slot);
        if (s) mt_node_on_udp(&node, &s->from, s->buf, s->len);
        mtp_udp_release(e->slot);
        break;
    }
    case MTP_EV_CALL:
        e->fn(&node, e->arg);
        break;
    case MTP_EV_CONNECT:
    case MTP_EV_SCAN:
    case MTP_EV_IP:
        mtp_netctl_event(&node, e);
        break;
    default:
        break;
    }
}

/* Safe mode or no store: Wi-Fi only (OTA and netlog stay reachable); the fault counter clears after the stable
 * period, so the next reset (an OTA install, a power cycle) tries Matter again. */
__attribute__((noreturn)) static void idle_forever(bool count_stable)
{
    mtp_event e;
    TickType_t stable_at = xTaskGetTickCount() + pdMS_TO_TICKS(MTP_SAFE_STABLE_MS);
    mtp_netctl_rescue("no Matter node");   /* OTA must stay reachable */
    for (;;) {
        if (xQueueReceive(queue, &e, pdMS_TO_TICKS(10000)) == pdTRUE && e.kind == MTP_EV_RX) mtp_udp_release(e.slot);
        if (count_stable && (int32_t)(xTaskGetTickCount() - stable_at) >= 0) {
            mtp_boot_stable();
            count_stable = false;
        }
    }
}


/* IM trace (mtp_app.im_trace): one line per IM message. */
static void im_trace(void *ctx, bool tx, uint16_t session, uint8_t opcode, size_t len, mt_err err)
{
    (void)ctx;
    MTP_LOG("im %lu %s s%u op %02x len %u%s\r\n", (unsigned long)mtp_now_ms(NULL), tx ? "tx" : "rx", session, opcode,
            (unsigned)len, err ? " SEND-ERR" : "");
}

static void matter_task(void *arg)
{
    static mt_node_credentials cred;
    mt_node_cfg cfg;
    mtp_kv *kv;
    bool safe;
    mt_err e;
    TickType_t stable_at;
    bool stable_done = false;
    uint32_t hold;
    (void)arg;

    if ((hold = mtp_boot_hold_ms())) {
        MTP_LOG("watchdog reset: store and node held for %lu s (OTA window)\r\n", (unsigned long)(hold / 1000u));
        vTaskDelay(pdMS_TO_TICKS(hold));
    }
    if (mtp_store_init() != MT_OK) {
        MTP_LOG("store unavailable: node not started\r\n");
        idle_forever(false);
    }
    safe = mtp_boot_begin();
    mtp_netctl_load();
    if (safe) idle_forever(true);
    if (mtp_store_load() != MT_OK) {
        MTP_LOG("store unavailable: node not started\r\n");
        idle_forever(false);
    }

    kv = mtp_store();
    mtp_kv_set_busy(kv, kv_busy, &node);
    if (!mtp_udp_start()) MTP_LOG("udp task create failed\r\n");
    if ((e = mtp_creds_build(app->cred, &cred))) {
        MTP_LOG("bad credentials (%d): node not started\r\n", (int)e);
        idle_forever(true);
    }

    cfg = app->node;
    memset(&cfg.ports, 0, sizeof cfg.ports);
    cfg.ports.ctx = &node;
    cfg.ports.now_ms = mtp_now_ms;
    cfg.ports.udp_send = mtp_udp_send;
    cfg.ports.entropy = mtp_entropy;
    cfg.ports.kv = mtp_kv_ops_of(kv);
    cfg.ports.cred = &cred;
    cfg.ports.net = mtp_netctl_ops();
    cfg.ports.iface = mtp_iface;
    cfg.ports.mdns_changed = mtp_mdns_changed;
    cfg.ports.ble_send = mtp_ble_send;
    cfg.ports.ble_close = mtp_ble_close;
    cfg.ports.ble_window = mtp_ble_window;
    if (app->im_trace) cfg.ports.im_trace = im_trace;
    mtp_ble_init(app->cred);
    cfg.boot_reason = mtp_boot_reason();
    if ((e = mt_node_init(&node, &cfg))) {
        MTP_LOG("mt_node_init failed (%d)\r\n", (int)e);
        idle_forever(true);
    }
    running = true;
    MTP_LOG("node up: reboot count %u, window %s\r\n", mt_node_reboot_count(&node),
            mt_node_window_open(&node) ? "open" : "closed");
    if (app->started) app->started(app->ctx, &node);

    stable_at = xTaskGetTickCount() + pdMS_TO_TICKS(MTP_SAFE_STABLE_MS);
    for (;;) {
        mtp_event ev;
        uint32_t wait;
        mtp_ble_drain(&node);
        wait = mt_node_poll(&node);
        wait = mt_min_u32(wait, mtp_ble_poll(kv));
        if (app->poll) wait = mt_min_u32(wait, app->poll(app->ctx, &node));
        wait = mt_min_u32(wait, mtp_netctl_poll(&node));
        if (mtp_kv_deferred(kv)) {
            if (!kv_busy(&node) && mtp_kv_flush(kv) != MT_OK) MTP_LOG("deferred kv write failed\r\n");
            if (mtp_kv_deferred(kv)) wait = mt_min_u32(wait, FLUSH_RETRY_MS);
        }
        if (!stable_done) {
            int32_t left = (int32_t)(stable_at - xTaskGetTickCount());
            if (left <= 0 && !mt_node_ble_connected(&node)) {   /* a flash write: not under a BLE link */
                mtp_boot_stable();
                stable_done = true;
            } else {
                wait = mt_min_u32(wait, left > 0 ? (uint32_t)left : 1000u);
            }
        }
        if (xQueueReceive(queue, &ev, wait == UINT32_MAX ? portMAX_DELAY : (TickType_t)wait /* 1 tick = 1 ms */) == pdTRUE) handle(&ev);
    }
}

static void factory_reset(mt_node *n, void *arg)
{
    (void)arg;
    MTP_LOG("factory reset: %u fabric(s) and the stored network go, rebooting\r\n", mt_fabric_count(&n->fabrics));
    mt_node_factory_reset(n);
    if (mtp_netctl_forget() != MT_OK) MTP_LOG("factory reset: network erase failed\r\n");
    if (mtp_kv_flush(mtp_store()) != MT_OK) MTP_LOG("factory reset: kv flush failed\r\n");
    vTaskDelay(pdMS_TO_TICKS(200));   /* the log line out to netlog */
    sys_reset();
}

bool mtp_factory_reset(void) { return mtp_call(factory_reset, NULL); }

bool mtp_start(const mtp_app *a)
{
    if (!a || app) return false;
    app = a;
    /* Wi-Fi first and unconditionally: OTA and netlog must not depend on the queue, the store or the node. */
    queue = xQueueCreate(QUEUE_LEN, sizeof(mtp_event));
    mtp_netctl_start(a);
    if (!a->cred || !queue || !mtp_rng_init()) return false;
    return xTaskCreate(matter_task, "matter", TASK_STACK_WORDS, NULL, TASK_PRIORITY, NULL) == pdPASS;
}
