// See thermo_link.h. 500 ms write debounce, resync with a full query when a report or write is dropped, MCU Wi-Fi
// icon from the network state.
#include "thermo_link.h"

#include <stdio.h>

#include "FreeRTOS.h"
#include "queue.h"
#include "task.h"

#include "lwip_netconf.h" // xnetif

#include "clock.h"       // SNTP time
#include "dp_cache.h"    // every DP for the web page
#include "matter_config.h"
#include "mt_thermostat.h"
#include "mtp_port.h"
#include "thermo_mcu.h" // TuyaMCU glue
#include "tuyamcu_port.h"

#define REPORT_QUEUE_LEN  24     // the MCU reports ~19 DPs at once; only the thermo ones are queued
#define WRITE_DEBOUNCE_MS 500u   // the Home app slider sends a burst of writes
#define TICK_MS           1000u  // resync, network status
#define UTC_REFRESH_MS    (6u * 3600u * 1000u) // SNTP time handed to the node again (tick drift)
#define MATTER_EPOCH_UNIX 946684800LL          // 2000-01-01 in Unix seconds

typedef struct {
    uint8_t dp;
    int32_t value;
} report;

static thermo model;
static mt_thermostat ts;
static QueueHandle_t reports;
static bool linked;                // thermo_link_start succeeded: the Matter task hooks do nothing without it
static volatile bool resync;       // a report or write was dropped: ask the MCU for everything again
static volatile bool ready;
static volatile bool wake_pending; // one wake per batch: the port's event queue is shared with UDP and Wi-Fi
static bool write_due;
static uint32_t write_at, tick_at;
static uint8_t net_sent = 0xFF;    // last TM_NET_* status sent to the MCU (0xFF = none; 0 is TM_NET_PAIRING)
static bool utc_given;
static uint32_t utc_at;            // when to hand the SNTP time to the node again

static uint32_t now_ms(void) { return (uint32_t) xTaskGetTickCount(); } // 1 kHz tick, as the port's clock
static uint32_t ts_now(void *ctx) { (void) ctx; return now_ms(); }

// ----- MCU -> Matter (TuyaMCU port task)

static void on_event(const tm_event *ev, void *ctx) {
    (void) ctx;
    switch (ev->type) {
        case TM_EV_LINK_UP: printf("mcu: link up\n"); break;
        case TM_EV_LINK_DOWN: printf("mcu: link down\n"); break;
        case TM_EV_PRODUCT: printf("mcu: product info %u bytes\n", (unsigned) ev->len); break;
        case TM_EV_WIFI_RESET:
            // The thermostat's own pairing gesture (the stock firmware's Wi-Fi reset): Matter factory reset.
            printf("mcu: wifi reset requested (mode %u): Matter factory reset\n", ev->arg);
            if (!mtp_factory_reset()) printf("mcu: factory reset could not be queued\n");
            break;
        case TM_EV_DP: {
            dp_cache_put(ev->dp);
            report r = { .dp = ev->dp->id };
            if (thermo_mcu_report(ev->dp, &r.value)) {
                if (xQueueSend(reports, &r, 0) == pdTRUE) {
                    if (!wake_pending) {
                        wake_pending = true;
                        mtp_wake();
                    }
                } else {
                    resync = true;
                }
            }
            break;
        }
    }
}

// ----- Setup (main)

// mt_thermostat, Matter task: Matter changed the model; the DP writes go out after the debounce.
static void on_write(void *ctx) {
    (void) ctx;
    write_due = true;                         // restart the debounce: the last write of a burst wins
    write_at = now_ms() + WRITE_DEBOUNCE_MS;
}

bool thermo_link_start(void) {
    static const thermo_cfg cfg = TM_THERMO_CFG;
    static const tuyamcu_port_config port = { .on_event = on_event, .get_time = thermo_mcu_time };
    thermo_init(&model, &cfg);
    reports = xQueueCreate(REPORT_QUEUE_LEN, sizeof(report));
    if (!reports || mt_thermostat_init(&ts, &(const mt_thermostat_cfg) { .model = &model, .now_ms = ts_now,
                                                                       .on_write = on_write,
                                                                       .identify_type = MT_IDENTIFY_TYPE_NONE,
                                                                       .auto_mode = TM_AUTO_MODE })) {
        return false;
    }
    if (!tuyamcu_port_start(&port)) {
        return false;
    }
    linked = true;
    return true;
}

const mt_dm_endpoint *thermo_link_endpoints(uint8_t *count) {
    *count = mt_thermostat_endpoint_count(&ts);
    return mt_thermostat_endpoint(&ts);
}

bool thermo_link_ready(void) { return ready; }

// ----- Matter -> MCU and housekeeping (Matter task)

static void flush_writes(void) {
    thermo_write w[THERMO_MAX_WRITES];
    size_t n = thermo_take_writes(&model, w, THERMO_MAX_WRITES, now_ms());
    for (size_t i = 0; i < n; i++) {
        printf("thermo: write dp %u = %ld\n", w[i].dp, (long) w[i].value);
        if (!thermo_mcu_write(w[i].dp, (thermo_wtype) w[i].type, w[i].value)) {
            resync = true;
        }
    }
}

static bool have_ip(void) { return ip4_addr_get_u32(netif_ip4_addr(&xnetif[0])) != 0; }

static void update_net_status(mt_node *n) {
    uint8_t status = mt_node_ble_on(n)                           ? TM_NET_PAIRING : // BLE window: blinking icon
                     !have_ip()                                  ? TM_NET_NO_LINK :
                     mt_fabric_committed_count(&n->fabrics) > 0 ? TM_NET_PAIRED :
                                                                  TM_NET_UNPAIRED;
    if (status != net_sent && tuyamcu_port_set_net_status(status)) {
        net_sent = status;
    }
}

// SNTP time for the node's certificate validity checks, so it doesn't depend on a commissioner's SetUTCTime.
static void update_utc(mt_node *n, uint32_t now) {
    if (utc_given && !mt_due(now, utc_at)) {
        return;
    }
    int64_t unix_s = clock_unix();
    if (unix_s <= MATTER_EPOCH_UNIX) {
        return; // not synced yet
    }
    uint64_t matter_us = (uint64_t) (unix_s - MATTER_EPOCH_UNIX) * 1000000u;
    if (mt_node_set_utc(n, matter_us, MT_TIME_GRAN_SECONDS, MT_TIME_SRC_NONMATTER_SNTP) == MT_OK) {
        if (!utc_given) {
            printf("matter: utc from sntp %lld\n", (long long) unix_s);
        }
        utc_given = true;
        utc_at = now + UTC_REFRESH_MS;
    }
}

void thermo_link_started(mt_node *n) {
    (void) n;
    if (!linked) {
        return;
    }
    if (!tuyamcu_port_query_all()) {
        resync = true;
    }
    tick_at = now_ms();
}

uint32_t thermo_link_poll(mt_node *n) {
    if (!linked) {
        return UINT32_MAX; // no queue, no port: the node still runs for OTA and the self-check's rollback
    }
    uint32_t now = now_ms(), wait;
    report r;
    wake_pending = false; // before draining: a report queued after this wakes the task again
    while (xQueueReceive(reports, &r, 0) == pdTRUE) {
        thermo_report(&model, r.dp, r.value, now);
    }
    if (!ready && thermo_ready(&model)) {
        ready = true;
        printf("thermo: ready (setpoint %ld, room %ld tenths C)\n", (long) thermo_target_tenths(&model),
               (long) thermo_current_tenths(&model));
    }
    if (write_due && mt_due(now, write_at)) {
        write_due = false;
        flush_writes();
    }
    if (mt_due(now, tick_at)) {
        tick_at = now + TICK_MS;
        if (resync && tuyamcu_port_query_all()) {
            resync = false;
        }
        update_net_status(n);
        update_utc(n, now);
    }
    wait = mt_thermostat_tick(&ts, &n->dm); // thermo_tick (pending holds), report sync, identify countdown
    wait = mt_min_u32(wait, mt_until(now, tick_at));
    if (write_due) {
        wait = mt_min_u32(wait, mt_until(now, write_at));
    }
    return wait;
}
