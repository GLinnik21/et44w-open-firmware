/* BLE task and Realtek glue for Matter commissioning (see include/btp_port.h). The init/teardown sequence is the
 * one measured with libs/ble-probe on the device: the stack costs its heap only while up, and bte_deinit gives all
 * but ~2.4 KiB of it back (hence one start per boot). */
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"

#include <app_msg.h>
#include <bte.h>
#include <ftl_int.h>
#include <gap.h>
#include <gap_adv.h>
#include <gap_bond_le.h>
#include <gap_config.h>
#include <gap_conn_le.h>
#include <gap_le.h>
#include <gap_msg.h>
#include <os_msg.h>
#include <profile_server.h>
#include <rtk_coex.h>
#include <trace_app.h>
#include <wifi_conf.h>

#include "platform_opts.h"

#include "btp_port.h"

#define LOG(...) printf("ble: " __VA_ARGS__)

#define TASK_STACK_WORDS 512
#define TASK_PRIORITY (tskIDLE_PRIORITY + 2)  /* above the Matter task: GATT callbacks never wait on Matter work */
#define MAX_GAP_MSG 0x10
#define MAX_IO_MSG 0x10
#define N_EVENTS 9    /* 8 usable: the BTP receive window (5) + connect/MTU/CCCD/sent, the last one kept for DISCONNECTED */
#define FAST_ADV_MS 30000u
#define FAST_MIN 32                           /* 20 ms in 0.625 ms units */
#define FAST_MAX 96                           /* 60 ms */
#define SLOW_MIN 240                          /* 150 ms */
#define SLOW_MAX 1920                         /* 1200 ms */
#define STOP_WAIT_MS 5000
#define REQ_POST_MS 1000                      /* a full event queue: the BLE task is far behind */
#define WAIT_FOREVER 0xFFFFFFFFu

/* Requests from the Matter task: T_IO_MSG with this type (the stack only posts IO_MSG_TYPE_BT_STATUS). */
#define REQ_TYPE 0x7E00u
enum { REQ_ADV_ON, REQ_ADV_OFF, REQ_SEND, REQ_DISCONNECT, REQ_STOP };

/* Matter BTP characteristic UUIDs 18EE2EF5-263D-4559-959F-4F9C429F9D11/12, little-endian. */
#define BTP_UUID(last) 0x##last, 0x9D, 0x9F, 0x42, 0x9C, 0x4F, 0x9F, 0x95, 0x59, 0x45, 0x3D, 0x26, 0xF5, 0x2E, 0xEE, 0x18
#define MATTER_SVC_UUID 0xFFF6
#define C1_INDEX 2
#define C2_INDEX 4

static const T_ATTRIB_APPL btp_table[] = {
    { ATTRIB_FLAG_VALUE_INCL | ATTRIB_FLAG_LE,
      { LO_WORD(GATT_UUID_PRIMARY_SERVICE), HI_WORD(GATT_UUID_PRIMARY_SERVICE), LO_WORD(MATTER_SVC_UUID),
        HI_WORD(MATTER_SVC_UUID) },
      UUID_16BIT_SIZE, NULL, GATT_PERM_READ },
    /* C1: central -> device, write with response */
    { ATTRIB_FLAG_VALUE_INCL,
      { LO_WORD(GATT_UUID_CHARACTERISTIC), HI_WORD(GATT_UUID_CHARACTERISTIC), GATT_CHAR_PROP_WRITE }, 1, NULL,
      GATT_PERM_READ },
    { ATTRIB_FLAG_VALUE_APPL | ATTRIB_FLAG_UUID_128BIT, { BTP_UUID(11) }, 0, NULL, GATT_PERM_WRITE },
    /* C2: device -> central, indications */
    { ATTRIB_FLAG_VALUE_INCL,
      { LO_WORD(GATT_UUID_CHARACTERISTIC), HI_WORD(GATT_UUID_CHARACTERISTIC), GATT_CHAR_PROP_INDICATE }, 1, NULL,
      GATT_PERM_READ },
    { ATTRIB_FLAG_VALUE_APPL | ATTRIB_FLAG_UUID_128BIT, { BTP_UUID(12) }, 0, NULL, GATT_PERM_NONE },
    { ATTRIB_FLAG_VALUE_INCL | ATTRIB_FLAG_CCCD_APPL,
      { LO_WORD(GATT_UUID_CHAR_CLIENT_CONFIG), HI_WORD(GATT_UUID_CHAR_CLIENT_CONFIG),
        LO_WORD(GATT_CLIENT_CHAR_CONFIG_DEFAULT), HI_WORD(GATT_CLIENT_CHAR_CONFIG_DEFAULT) },
      2, NULL, GATT_PERM_READ | GATT_PERM_WRITE },
};

static btpp_cfg cfg;
static volatile btpp_state state = BTPP_OFF;
static TaskHandle_t task;
static SemaphoreHandle_t stop_sem;
static void *evt_queue, *io_queue;
static T_SERVER_ID btp_id;
static volatile bool stop_early;              /* btpp_stop before the stack came up */
static bool stack_inited;
static bool stop_timed_out;                   /* btpp_stop gave up: the radio may still be on */
static uint8_t adv_data[15];

/* BLE task state */
static bool want_adv, stopping, fast, restart;
static volatile bool connected;               /* also read by btpp_send (Matter task) */
static uint8_t adv_state = GAP_ADV_STATE_IDLE;
static bool linking;   /* advertising stopped for an incoming link; its conn-state event hasn't come yet */
static uint32_t rejecting;   /* bit per conn id: refused at CONNECTED (le_disconnect sent), no DISCONNECTED yet */
static uint8_t conn_id;
static TickType_t fast_until;

/* outgoing indication: written by the Matter task while !tx_busy, read by the BLE task */
static volatile bool tx_busy;
static uint8_t tx_buf[BTPP_DATA_MAX];
static uint16_t tx_len;

/* event ring: BLE task produces, Matter task consumes */
static btpp_event ring[N_EVENTS];
static volatile uint8_t ring_head, ring_tail;

#define BARRIER() __asm volatile("" ::: "memory")

/* The last free slot is kept for DISCONNECTED: every other event of a link needs two, so a link whose CONNECTED went
 * into the ring always gets its DISCONNECTED in too (a full ring drops the link, see link_event). */
static bool push(uint8_t kind, uint16_t val, const uint8_t *data, uint16_t len)
{
    uint8_t t = ring_tail;
    uint8_t used = (uint8_t)((t + N_EVENTS - ring_head) % N_EVENTS), room = (uint8_t)(N_EVENTS - 1 - used);
    if (room == 0 || (room == 1 && kind != BTPP_EV_DISCONNECTED)) return false;
    ring[t].kind = kind;
    ring[t].val = val;
    ring[t].len = len;
    if (len) memcpy(ring[t].data, data, len);
    BARRIER();
    ring_tail = (uint8_t)((t + 1) % N_EVENTS);
    if (cfg.notify) cfg.notify();
    return true;
}

/* A lost event (ring full: the Matter task is far behind) would desynchronize BTP: drop the link instead. Events of
 * the current link only (connected); its DISCONNECTED always fits (push). */
static void link_event(uint8_t kind, uint16_t val, const uint8_t *data, uint16_t len)
{
    if (!connected || push(kind, val, data, len)) return;
    LOG("event ring full (ev %u), disconnecting\r\n", kind);
    le_disconnect(conn_id);
}

bool btpp_next(btpp_event *out)
{
    uint8_t h = ring_head;
    if (h == ring_tail) return false;
    BARRIER();
    memcpy(out, &ring[h], offsetof(btpp_event, data) + ring[h].len);
    BARRIER();
    ring_head = (uint8_t)((h + 1) % N_EVENTS);
    return true;
}

btpp_state btpp_get_state(void) { return state; }

/* Posts a request: the IO message first (the BLE task runs at a higher priority and reads it as soon as the event
 * is posted), then its event. false = not posted. If the event can't be posted, the message stays queued and runs
 * with the next event (the task drains every queued IO message per event), so it counts as posted. */
static bool request(uint16_t sub)
{
    T_IO_MSG m;
    uint8_t ev = EVENT_IO_TO_APP;
    if (!io_queue || !evt_queue) return false;
    m.type = REQ_TYPE;
    m.subtype = sub;
    m.u.param = 0;
    if (!os_msg_send(io_queue, &m, 0)) return false;
    if (!os_msg_send(evt_queue, &ev, REQ_POST_MS)) LOG("request %u: event queue full, runs with the next event\r\n", sub);
    return true;
}

/* ---- advertising ---- */
static void adv_params(bool is_fast)
{
    uint16_t min = is_fast ? FAST_MIN : SLOW_MIN, max = is_fast ? FAST_MAX : SLOW_MAX;
    le_adv_set_param(GAP_PARAM_ADV_INTERVAL_MIN, sizeof min, &min);
    le_adv_set_param(GAP_PARAM_ADV_INTERVAL_MAX, sizeof max, &max);
}

/* Starts advertising if wanted and possible; intervals can only change while idle. */
static void adv_kick(void)
{
    if (stopping || !want_adv || connected || linking || rejecting || adv_state != GAP_ADV_STATE_IDLE || state != BTPP_READY) return;
    if (fast && (int32_t)(xTaskGetTickCount() - fast_until) >= 0) fast = false;
    adv_params(fast);
    if (le_adv_start() != GAP_CAUSE_SUCCESS) LOG("adv start failed\r\n");
}

/* (Re)start in the fast phase. A running advertisement is stopped first (idle -> adv_kick); one in a transient
 * state is stopped once it reports ADVERTISING. */
static void adv_fast_restart(void)
{
    fast = true;
    fast_until = xTaskGetTickCount() + pdMS_TO_TICKS(FAST_ADV_MS);
    if (adv_state == GAP_ADV_STATE_IDLE) adv_kick();
    else if (adv_state == GAP_ADV_STATE_ADVERTISING) le_adv_stop();
    else restart = true;
}

static void adv_stop(void)
{
    if (adv_state == GAP_ADV_STATE_ADVERTISING) le_adv_stop();
    else if (adv_state == GAP_ADV_STATE_START) restart = true;   /* stopped when it reports ADVERTISING */
}

/* REQ_STOP waits for a ready stack (a deinit during startup is not something Realtek's examples do). */
static void check_stopped(void)
{
    if (stopping && state == BTPP_READY && adv_state == GAP_ADV_STATE_IDLE && !connected && !linking && !rejecting) {
        xSemaphoreGive(stop_sem);
        vTaskSuspend(NULL);                   /* deleted by btpp_stop */
    }
}

/* ---- GATT ---- */
static T_APP_RESULT btp_write(uint8_t cid, T_SERVER_ID id, uint16_t index, T_WRITE_TYPE type, uint16_t len,
                              uint8_t *value, P_FUN_WRITE_IND_POST_PROC *post)
{
    (void)id;
    (void)type;
    *post = NULL;
    if (index != C1_INDEX || cid != conn_id || !connected) return APP_RESULT_ATTR_NOT_FOUND;
    if (len > BTPP_DATA_MAX) return APP_RESULT_INVALID_VALUE_SIZE;
    link_event(BTPP_EV_WRITE, 0, value, len);
    return APP_RESULT_SUCCESS;
}

static void btp_cccd(uint8_t cid, T_SERVER_ID id, uint16_t index, uint16_t bits)
{
    (void)id;
    (void)index;
    if (cid != conn_id || !connected) return;
    link_event((bits & GATT_CLIENT_CHAR_CONFIG_INDICATE) ? BTPP_EV_SUBSCRIBED : BTPP_EV_UNSUBSCRIBED, 0, NULL, 0);
}

static const T_FUN_GATT_SERVICE_CBS btp_cbs = { NULL, btp_write, btp_cccd };

static T_APP_RESULT profile_cb(T_SERVER_ID id, void *data)
{
    T_SERVER_APP_CB_DATA *d = data;
    if (id == SERVICE_PROFILE_GENERAL_ID && d->eventId == PROFILE_EVT_SEND_DATA_COMPLETE &&
        d->event_data.send_data_result.service_id == btp_id && tx_busy) {
        uint16_t cause = d->event_data.send_data_result.cause;
        tx_busy = false;
        link_event(BTPP_EV_SENT, cause == GAP_SUCCESS ? 0 : (cause ? cause : 1), NULL, 0);
    }
    return APP_RESULT_SUCCESS;
}

static T_APP_RESULT gap_cb(uint8_t type, void *data)
{
    (void)type;
    (void)data;
    return APP_RESULT_SUCCESS;
}

/* ---- events of the BLE task ---- */
static void on_dev_state(T_GAP_DEV_STATE s)
{
    if (state == BTPP_STARTING && s.gap_init_state == GAP_INIT_STATE_STACK_READY) {
        state = BTPP_READY;
        LOG("stack ready, heap free %u, min ever %u\r\n", (unsigned)xPortGetFreeHeapSize(),
            (unsigned)xPortGetMinimumEverFreeHeapSize());
    }
    adv_state = s.gap_adv_state;
    if (adv_state == GAP_ADV_STATE_ADVERTISING && (restart || stopping || !want_adv)) {
        restart = false;
        le_adv_stop();
    } else if (adv_state == GAP_ADV_STATE_IDLE) {
        restart = false;                      /* whatever it was stopped for, adv_kick applies the current phase */
        if (s.gap_adv_sub_state == GAP_ADV_TO_IDLE_CAUSE_CONN) linking = true;   /* restarting now would fail */
        check_stopped();
        adv_kick();
    }
}

/* Refuses a link the Matter side never hears of. It stays up until its DISCONNECTED (rejecting holds off the stop
 * acknowledgement and advertising till then). */
static void reject(uint8_t cid)
{
    rejecting |= 1u << (cid & 31);
    le_disconnect(cid);
}

static void on_conn_state(uint8_t cid, uint8_t st, uint16_t cause)
{
    bool was_rejected = (rejecting >> (cid & 31)) & 1u;
    if (st == GAP_CONN_STATE_DISCONNECTED) rejecting &= ~(1u << (cid & 31));   /* whichever branch takes it */
    if (linking && (st == GAP_CONN_STATE_CONNECTED || st == GAP_CONN_STATE_DISCONNECTED)) {
        linking = false;
        if (st == GAP_CONN_STATE_DISCONNECTED && !connected) {   /* the link never came up */
            check_stopped();
            adv_kick();
        }
    }
    if (st == GAP_CONN_STATE_CONNECTED) {
        if (connected || stopping) {          /* one link only; none while stopping */
            reject(cid);
            return;
        }
        conn_id = cid;
        tx_busy = false;
        connected = true;                     /* before the event: btpp_send may run as soon as it is seen */
        if (!push(BTPP_EV_CONNECTED, 0, NULL, 0)) {   /* ring full: the Matter task is far behind */
            connected = false;
            LOG("event ring full, refusing a link\r\n");
            reject(cid);
            return;
        }
        LOG("connected, heap free %u\r\n", (unsigned)xPortGetFreeHeapSize());
    } else if (st == GAP_CONN_STATE_DISCONNECTED && connected && cid == conn_id) {
        connected = false;
        tx_busy = false;
        LOG("disconnected (0x%x)\r\n", cause);
        (void)push(BTPP_EV_DISCONNECTED, cause, NULL, 0);   /* always fits: the slot kept for it */
        check_stopped();
        if (want_adv) adv_fast_restart();
    } else if (st == GAP_CONN_STATE_DISCONNECTED && was_rejected) {
        check_stopped();
        adv_kick();
    }
}

static void on_gap_msg(T_IO_MSG *m)
{
    T_LE_GAP_MSG g;
    memcpy(&g, &m->u.param, sizeof m->u.param);
    switch (m->subtype) {
    case GAP_MSG_LE_DEV_STATE_CHANGE:
        on_dev_state(g.msg_data.gap_dev_state_change.new_state);
        break;
    case GAP_MSG_LE_CONN_STATE_CHANGE:
        on_conn_state(g.msg_data.gap_conn_state_change.conn_id, g.msg_data.gap_conn_state_change.new_state,
                      g.msg_data.gap_conn_state_change.disc_cause);
        break;
    case GAP_MSG_LE_CONN_MTU_INFO:
        if (connected && g.msg_data.gap_conn_mtu_info.conn_id == conn_id)
            link_event(BTPP_EV_MTU, g.msg_data.gap_conn_mtu_info.mtu_size, NULL, 0);
        break;
    default:
        break;
    }
}

static void on_request(uint16_t sub)
{
    switch (sub) {
    case REQ_ADV_ON:
        want_adv = true;
        adv_fast_restart();
        break;
    case REQ_ADV_OFF:
        want_adv = false;
        adv_stop();
        break;
    case REQ_SEND:
        if (!connected ||
            !server_send_data(conn_id, btp_id, C2_INDEX, tx_buf, tx_len, GATT_PDU_TYPE_INDICATION)) {
            tx_busy = false;
            link_event(BTPP_EV_SENT, 1, NULL, 0);
        }
        break;
    case REQ_DISCONNECT:
        if (connected) le_disconnect(conn_id);
        break;
    case REQ_STOP:
        stopping = true;
        want_adv = false;
        adv_stop();
        if (connected) le_disconnect(conn_id);
        check_stopped();
        break;
    }
}

static void configure(void)
{
    char name[GAP_DEVICE_NAME_LEN] = { 0 };   /* the whole buffer is passed: no stack bytes in the name */
    uint8_t pair = GAP_PAIRING_MODE_NO_PAIRING;
    uint8_t evt = GAP_ADTYPE_ADV_IND, chan = GAP_ADVCHAN_ALL, filt = GAP_ADV_FILTER_ANY;
    snprintf(name, sizeof name, "MATTER-%04u", (unsigned)cfg.discriminator); /* chip's GAP name convention */
    le_set_gap_param(GAP_PARAM_DEVICE_NAME, GAP_DEVICE_NAME_LEN, name);
    gap_set_param(GAP_PARAM_BOND_PAIRING_MODE, sizeof pair, &pair);
    le_adv_set_param(GAP_PARAM_ADV_EVENT_TYPE, sizeof evt, &evt);
    le_adv_set_param(GAP_PARAM_ADV_CHANNEL_MAP, sizeof chan, &chan);
    le_adv_set_param(GAP_PARAM_ADV_FILTER_POLICY, sizeof filt, &filt);
    adv_params(true);
    le_adv_set_param(GAP_PARAM_ADV_DATA, sizeof adv_data, adv_data);
    le_register_app_cb(gap_cb);
    server_init(1);
    server_add_service(&btp_id, (uint8_t *)btp_table, sizeof btp_table, btp_cbs);
    server_register_app_cb(profile_cb);
}

/* Start failed: FAILED for good (btpp_stop is then a no-op, so nothing is torn down under the task), task parked. */
__attribute__((noreturn)) static void fail_park(const char *what)
{
    LOG("%s failed: BLE off until reboot, heap free %u\r\n", what, (unsigned)xPortGetFreeHeapSize());
    state = BTPP_FAILED;
    for (;;) vTaskSuspend(NULL);
}

static void ble_task(void *arg)
{
    (void)arg;
    /* As the SDK examples: BT comes up after Wi-Fi (coexistence), its bond storage (FTL) lives in sdk_reserved. */
    while (!wifi_is_up(RTW_STA_INTERFACE) && !stop_early) vTaskDelay(pdMS_TO_TICKS(200));
    if (stop_early) {
        xSemaphoreGive(stop_sem);
        vTaskSuspend(NULL);
    }
    LOG("starting, heap free %u\r\n", (unsigned)xPortGetFreeHeapSize());
    ftl_init(BT_FTL_BKUP_ADDR, 3);
    gap_config_max_le_link_num(1);
    gap_config_max_le_paired_device(1);
    gap_config_deinit_flow(1);
    bt_trace_init();
    if (!bte_init()) fail_park("bte_init");   /* nothing of the stack runs: nothing to deinit */
    le_gap_init(1);
    configure();
    stack_inited = true;
    /* A stack that never reached READY is not deinitialized (as Realtek's ble_matter_adapter): it stays allocated. */
    if (!gap_start_bt_stack(evt_queue, io_queue, MAX_GAP_MSG)) fail_park("gap_start_bt_stack");
    bt_coex_init();

    for (;;) {
        uint8_t ev;
        uint32_t wait = WAIT_FOREVER;
        if (adv_state == GAP_ADV_STATE_ADVERTISING && fast) {
            int32_t left = (int32_t)(fast_until - xTaskGetTickCount());
            wait = left > 0 ? (uint32_t)left : 0;
        }
        if (os_msg_recv(evt_queue, &ev, wait)) {
            if (ev == EVENT_IO_TO_APP) {
                T_IO_MSG m;
                /* All queued messages: one whose event was lost (request) must not shift the others by one. */
                while (os_msg_recv(io_queue, &m, 0)) {
                    if (m.type == IO_MSG_TYPE_BT_STATUS) on_gap_msg(&m);
                    else if (m.type == REQ_TYPE) on_request(m.subtype);
                }
            } else {
                gap_handle_msg(ev);
            }
        } else if (adv_state == GAP_ADV_STATE_ADVERTISING && fast) {
            fast = false;                     /* fast phase over: idle -> adv_kick with the slow intervals */
            le_adv_stop();
        }
    }
}

bool btpp_start(const btpp_cfg *c)
{
    if (state != BTPP_OFF || !c) return false;
    cfg = *c;
    adv_data[0] = 0x02;
    adv_data[1] = GAP_ADTYPE_FLAGS;
    adv_data[2] = GAP_ADTYPE_FLAGS_GENERAL | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED;
    adv_data[3] = 0x0B;
    adv_data[4] = GAP_ADTYPE_SERVICE_DATA;
    adv_data[5] = LO_WORD(MATTER_SVC_UUID);
    adv_data[6] = HI_WORD(MATTER_SVC_UUID);
    adv_data[7] = 0x00;                                    /* opcode: commissionable */
    adv_data[8] = (uint8_t)(cfg.discriminator & 0xFF);     /* discriminator bits 0-7 */
    adv_data[9] = (uint8_t)((cfg.discriminator >> 8) & 0x0F); /* bits 8-11; advertisement version 0 above */
    adv_data[10] = (uint8_t)cfg.vendor_id;
    adv_data[11] = (uint8_t)(cfg.vendor_id >> 8);
    adv_data[12] = (uint8_t)cfg.product_id;
    adv_data[13] = (uint8_t)(cfg.product_id >> 8);
    adv_data[14] = 0x00;                                   /* no additional data (C3 not served) */
    stop_sem = xSemaphoreCreateBinary();
    os_msg_queue_create(&io_queue, MAX_IO_MSG, sizeof(T_IO_MSG));
    os_msg_queue_create(&evt_queue, MAX_GAP_MSG + MAX_IO_MSG, sizeof(uint8_t));
    state = BTPP_STARTING;
    if (!stop_sem || !io_queue || !evt_queue ||
        xTaskCreate(ble_task, "ble", TASK_STACK_WORDS, NULL, TASK_PRIORITY, &task) != pdPASS) {
        LOG("start failed (out of memory)\r\n");
        state = BTPP_FAILED;
        return false;
    }
    return true;
}

void btpp_advertise(bool on) { (void)request(on ? REQ_ADV_ON : REQ_ADV_OFF); }

bool btpp_send(const uint8_t *pkt, size_t len)
{
    if (state != BTPP_READY || !connected || tx_busy || len == 0 || len > sizeof tx_buf) return false;
    memcpy(tx_buf, pkt, len);
    tx_len = (uint16_t)len;
    tx_busy = true;
    if (!request(REQ_SEND)) {
        tx_busy = false;
        return false;
    }
    return true;
}

void btpp_disconnect(void) { (void)request(REQ_DISCONNECT); }

bool btpp_stop(void)
{
    if (state != BTPP_STARTING && state != BTPP_READY) return !stop_timed_out;
    stop_early = true;                        /* the task may still be waiting for Wi-Fi ... */
    (void)request(REQ_STOP);                  /* ... or runs its loop (the request waits in the queue till then) */
    if (xSemaphoreTake(stop_sem, pdMS_TO_TICKS(STOP_WAIT_MS)) != pdTRUE) {
        /* No acknowledgement: the task may be inside a Realtek call, and once gap_start_bt_stack ran the stack's
         * own tasks post into our queues. Deleting the task or the queues, or a deinit, could then corrupt memory:
         * leave everything allocated (REQ_STOP, if it is ever handled, still stops advertising) and never restart.
         * The radio may still be on: the caller must not write flash (see the header). */
        stop_timed_out = true;
        state = BTPP_STOPPED;
        LOG("stop: task did not settle, stack left as is, heap free %u\r\n", (unsigned)xPortGetFreeHeapSize());
        return false;
    }
    /* Acknowledged: the task is parked either before any stack call (stop_early) or in check_stopped, which only
     * acknowledges a READY stack with advertising idle and no link: the state Realtek's own deinit expects. */
    vTaskDelete(task);
    task = NULL;
    if (stack_inited) {
        bte_deinit();
        bt_trace_uninit();
    }
    os_msg_queue_delete(io_queue);
    os_msg_queue_delete(evt_queue);
    io_queue = evt_queue = NULL;
    vSemaphoreDelete(stop_sem);
    stop_sem = NULL;
    ring_head = ring_tail = 0;
    tx_busy = false;
    state = BTPP_STOPPED;
    LOG("stopped, heap free %u, min ever %u\r\n", (unsigned)xPortGetFreeHeapSize(),
        (unsigned)xPortGetMinimumEverFreeHeapSize());
    return true;
}
