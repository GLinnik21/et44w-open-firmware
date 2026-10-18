// Measurement probe for the Matter-commissioning BLE path: bring the Realtek BLE stack up, serve
// Matter's BTP GATT service (0xFFF6: C1 write, C2 indicate), advertise as a commissionable Matter
// device, then shut the stack down after a window, logging free heap at each step.
// Not product code: no BTP framing; a C1 write is echoed on C2 once the client subscribed to it.
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include <bte.h>
#include <gap.h>
#include <gap_adv.h>
#include <gap_config.h>
#include <gap_conn_le.h>
#include <gap_le.h>
#include <gap_msg.h>
#include <os_msg.h>
#include <os_task.h>
#include <profile_server.h>
#include <app_msg.h>
#include <rtk_coex.h>
#include <trace_app.h>
#include <ftl_int.h>
#include <wifi_conf.h>

#include "platform_opts.h"

#include "ble_probe.h"

extern int printf(const char *fmt, ...);

#define PROBE_WINDOW_MS (120 * 1000) // a commissioning window; Matter's default is 15 min
#define MAX_GAP_MSG     0x10
#define MAX_IO_MSG      0x10
#define STOP_WAIT_MS    5000 // advertising off and the link gone before bte_deinit

// Matter BTP characteristic UUIDs 18EE2EF5-263D-4559-959F-4F9C429F9D11/12, little-endian.
#define BTP_UUID(last) 0x##last, 0x9D, 0x9F, 0x42, 0x9C, 0x4F, 0x9F, 0x95, \
                       0x59, 0x45, 0x3D, 0x26, 0xF5, 0x2E, 0xEE, 0x18
#define MATTER_SVC_UUID 0xFFF6

static const T_ATTRIB_APPL btp_table[] = {
    { ATTRIB_FLAG_VALUE_INCL | ATTRIB_FLAG_LE,
      { LO_WORD(GATT_UUID_PRIMARY_SERVICE), HI_WORD(GATT_UUID_PRIMARY_SERVICE),
        LO_WORD(MATTER_SVC_UUID), HI_WORD(MATTER_SVC_UUID) },
      UUID_16BIT_SIZE, NULL, GATT_PERM_READ },
    // C1: client -> device
    { ATTRIB_FLAG_VALUE_INCL,
      { LO_WORD(GATT_UUID_CHARACTERISTIC), HI_WORD(GATT_UUID_CHARACTERISTIC), GATT_CHAR_PROP_WRITE },
      1, NULL, GATT_PERM_READ },
    { ATTRIB_FLAG_VALUE_APPL | ATTRIB_FLAG_UUID_128BIT, { BTP_UUID(11) }, 0, NULL, GATT_PERM_WRITE },
    // C2: device -> client (indications)
    { ATTRIB_FLAG_VALUE_INCL,
      { LO_WORD(GATT_UUID_CHARACTERISTIC), HI_WORD(GATT_UUID_CHARACTERISTIC), GATT_CHAR_PROP_INDICATE },
      1, NULL, GATT_PERM_READ },
    { ATTRIB_FLAG_VALUE_APPL | ATTRIB_FLAG_UUID_128BIT, { BTP_UUID(12) }, 0, NULL, GATT_PERM_NONE },
    { ATTRIB_FLAG_VALUE_INCL | ATTRIB_FLAG_CCCD_APPL,
      { LO_WORD(GATT_UUID_CHAR_CLIENT_CONFIG), HI_WORD(GATT_UUID_CHAR_CLIENT_CONFIG),
        LO_WORD(GATT_CLIENT_CHAR_CONFIG_DEFAULT), HI_WORD(GATT_CLIENT_CHAR_CONFIG_DEFAULT) },
      2, NULL, GATT_PERM_READ | GATT_PERM_WRITE },
};

// Flags + service data 0xFFF6: opcode 0, discriminator 0xF00 / version 0, test VID 0xFFF1, PID 0x8000.
static const uint8_t adv_data[] = {
    0x02, GAP_ADTYPE_FLAGS, GAP_ADTYPE_FLAGS_GENERAL | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED,
    0x0B, GAP_ADTYPE_SERVICE_DATA, LO_WORD(MATTER_SVC_UUID), HI_WORD(MATTER_SVC_UUID),
    0x00, 0x00, 0x0F, 0xF1, 0xFF, 0x00, 0x80, 0x00,
};

#define HEAP_LEAK_LIMIT 2048

static T_SERVER_ID btp_id;
static void (*on_done)(bool heap_ok);
static void *evt_queue, *io_queue;
// Link state: the probe task only (the GATT callbacks run from its gap_handle_msg)
static bool linked, subscribed;
static uint8_t link_id;

static void log_heap(const char *step)
{
    printf("[ble_probe] %s: heap free %u, min ever %u\r\n", step,
           (unsigned) xPortGetFreeHeapSize(), (unsigned) xPortGetMinimumEverFreeHeapSize());
}

#define BTP_C2_INDEX 4 // attribute index of the C2 value in btp_table

static T_APP_RESULT btp_write(uint8_t conn_id, T_SERVER_ID id, uint16_t index, T_WRITE_TYPE type,
                              uint16_t len, uint8_t *value, P_FUN_WRITE_IND_POST_PROC *post)
{
    *post = NULL;
    printf("[ble_probe] C1 write %u bytes\r\n", len);
    log_heap("connected");
    // Echo on C2 so the indication path is linked, as BTP needs it; only to a client that turned indications on.
    if (subscribed && linked && conn_id == link_id) {
        server_send_data(conn_id, id, BTP_C2_INDEX, value, len, GATT_PDU_TYPE_INDICATION);
    }
    return APP_RESULT_SUCCESS;
}

static void btp_cccd(uint8_t conn_id, T_SERVER_ID id, uint16_t index, uint16_t bits)
{
    printf("[ble_probe] C2 CCCD 0x%x\r\n", bits);
    subscribed = (bits & GATT_CLIENT_CHAR_CONFIG_INDICATE) != 0;
}

// Tracks the one link from the stack's conn-state messages.
static void on_io_msg(T_IO_MSG *msg)
{
    T_LE_GAP_MSG g;
    if (msg->type != IO_MSG_TYPE_BT_STATUS || msg->subtype != GAP_MSG_LE_CONN_STATE_CHANGE) {
        return;
    }
    memcpy(&g, &msg->u.param, sizeof(msg->u.param));
    if (g.msg_data.gap_conn_state_change.new_state == GAP_CONN_STATE_CONNECTED) {
        linked = true;
        subscribed = false;
        link_id = g.msg_data.gap_conn_state_change.conn_id;
    } else if (g.msg_data.gap_conn_state_change.new_state == GAP_CONN_STATE_DISCONNECTED &&
               g.msg_data.gap_conn_state_change.conn_id == link_id) {
        linked = subscribed = false;
    }
}

// One round of the stack's event loop.
static void pump_events(uint32_t wait_ms)
{
    uint8_t event;
    if (os_msg_recv(evt_queue, &event, wait_ms)) {
        if (event == EVENT_IO_TO_APP) {
            T_IO_MSG msg;
            while (os_msg_recv(io_queue, &msg, 0)) {
                on_io_msg(&msg);
            }
        } else {
            gap_handle_msg(event);
        }
    }
}

static const T_FUN_GATT_SERVICE_CBS btp_cbs = { NULL, btp_write, btp_cccd };

static T_APP_RESULT gap_cb(uint8_t type, void *data)
{
    return APP_RESULT_SUCCESS;
}

static void configure(void)
{
    uint8_t name[GAP_DEVICE_NAME_LEN] = "Thermostat";
    uint16_t interval = 160; // 100 ms
    le_set_gap_param(GAP_PARAM_DEVICE_NAME, GAP_DEVICE_NAME_LEN, name);
    le_adv_set_param(GAP_PARAM_ADV_INTERVAL_MIN, sizeof(interval), &interval);
    le_adv_set_param(GAP_PARAM_ADV_INTERVAL_MAX, sizeof(interval), &interval);
    le_adv_set_param(GAP_PARAM_ADV_DATA, sizeof(adv_data), (void *) adv_data);
    le_register_app_cb(gap_cb);
    server_init(1);
    server_add_service(&btp_id, (uint8_t *) btp_table, sizeof(btp_table), btp_cbs);
}

static void probe_task(void *arg)
{
    // As the SDK example: BT comes up after Wi-Fi, and its bond storage (FTL) lives in sdk_reserved.
    while (!wifi_is_up(RTW_STA_INTERFACE)) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    ftl_init(BT_FTL_BKUP_ADDR, 3);
    size_t before = xPortGetFreeHeapSize();
    log_heap("before BT");
    gap_config_max_le_link_num(1);
    gap_config_max_le_paired_device(1);
    gap_config_deinit_flow(1);
    bt_trace_init();
    bte_init();
    le_gap_init(1);
    configure();
    os_msg_queue_create(&io_queue, MAX_IO_MSG, sizeof(T_IO_MSG));
    os_msg_queue_create(&evt_queue, MAX_GAP_MSG + MAX_IO_MSG, sizeof(uint8_t));
    gap_start_bt_stack(evt_queue, io_queue, MAX_GAP_MSG);
    bt_coex_init();

    bool advertising = false;
    TickType_t until = xTaskGetTickCount() + pdMS_TO_TICKS(PROBE_WINDOW_MS);
    while ((int32_t) (until - xTaskGetTickCount()) > 0) {
        pump_events(1000); // dev-state changes are polled below
        T_GAP_DEV_STATE st;
        le_get_gap_param(GAP_PARAM_DEV_STATE, &st);
        if (!advertising && st.gap_init_state == GAP_INIT_STATE_STACK_READY) {
            advertising = le_adv_start() == GAP_CAUSE_SUCCESS;
            log_heap("advertising");
        }
    }

    // Realtek's deinit expects an idle stack: advertising stopped (reported, not just requested) and no link.
    le_adv_stop();
    if (linked) {
        le_disconnect(link_id);
    }
    bool idle = false;
    until = xTaskGetTickCount() + pdMS_TO_TICKS(STOP_WAIT_MS);
    while (!idle && (int32_t) (until - xTaskGetTickCount()) > 0) {
        pump_events(100);
        T_GAP_DEV_STATE st;
        le_get_gap_param(GAP_PARAM_DEV_STATE, &st);
        if (st.gap_adv_state == GAP_ADV_STATE_ADVERTISING) {
            le_adv_stop(); // was still starting when first asked
        }
        idle = st.gap_adv_state == GAP_ADV_STATE_IDLE && !linked;
    }
    if (!idle) {
        // Deinit under a live link or advertisement could corrupt memory: leave the stack up, report a failure.
        printf("[ble_probe] stack did not go idle, not deinitialized\r\n");
        if (on_done) {
            on_done(false);
        }
        vTaskDelete(NULL);
    }
    bte_deinit();
    bt_trace_uninit();
    os_msg_queue_delete(io_queue);
    os_msg_queue_delete(evt_queue);
    log_heap("after BT deinit");
    vTaskDelay(pdMS_TO_TICKS(2000)); // let the stack's own tasks finish deleting themselves
    size_t after = xPortGetFreeHeapSize();
    printf("[ble_probe] heap change across the BT cycle: %d bytes\r\n", (int) after - (int) before);
    if (on_done) {
        on_done(after + HEAP_LEAK_LIMIT >= before);
    }
    vTaskDelete(NULL);
}

void ble_probe_start(void (*done)(bool heap_ok))
{
    on_done = done;
    xTaskCreate(probe_task, "ble_probe", 512, NULL, tskIDLE_PRIORITY + 1, NULL);
}
