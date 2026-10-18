// See health.h.
#include "health.h"

#include <stdio.h>

#include "FreeRTOS.h"
#include "task.h"

#include "lwip/sockets.h"

#include "mtp_port.h"
#include "ota.h"
#include "ota_test.h"
#include "thermo_link.h"

#define S0_STACK_WORDS 768 // lwIP connect + printf; freed when the check ends

static volatile bool ip_up;
static void (*const confirm_hook)(void) = ota_test_confirm_hook; // NULL in OTA_TEST=never_confirm builds

void health_on_ip(void) { ip_up = true; }

static uint32_t uptime_ms(void) { return (uint32_t) xTaskGetTickCount(); }

// Does a local TCP service still accept connections? Connect to 127.0.0.1:port within 5 s, then close.
static bool tcp_answers(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return false;
    }
    struct timeval tv = { .tv_sec = 5 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port),
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bool ok = connect(fd, (struct sockaddr*) &addr, sizeof addr) == 0;
    close(fd);
    return ok;
}

static void s0_task(void *arg) {
    (void) arg;
    bool udp = false, run = false, thermo = false, ble = false;
    uint32_t net_from = 0; // HEALTH_NET_MS counts from here: boot, or the end of an offline BLE window
    bool said_offline = false;
    for (;;) {
        uint32_t t = uptime_ms();
        if (mtp_offline_for_ble()) {
            // Uncommissioned, waiting for a commissioner over BLE: no IP by design, so nothing to judge yet. Keep the
            // trial open (it can't confirm without IP) until commissioning or the rescue network brings Wi-Fi up;
            // the window is bounded (BLE_WINDOW_S), and so is the extension (OTA_TRIAL_MAX_MS).
            ota_extend_trial(OTA_TRIAL_MS);
            net_from = t;
            if (!said_offline) {
                printf("S0: offline for BLE commissioning at %lu s, waiting for IP\n", (unsigned long) (t / 1000));
                said_offline = true;
            }
        }
        udp = mtp_udp_bound();
        run = mtp_running();
        thermo = thermo_link_ready();
        ble = mtp_ble_settled(); // an uncommissioned unit measures the heap with BLE up (its worst case)
        if (ip_up && udp && run && thermo && ble) {
            break;
        }
        if ((!thermo && t >= HEALTH_THERMO_MS) || t - net_from >= HEALTH_NET_MS) {
            printf("S0: FAILED at %lu s: ip %d, udp %d, node %d, thermo %d, ble settled %d -> not confirming\n",
                   (unsigned long) (t / 1000), (int) ip_up, (int) udp, (int) run, (int) thermo, (int) ble);
            vTaskDelete(NULL);
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    // IP usually comes from a commissioning still in progress (BLE, PASE and CASE all hold heap): resample until the
    // heap recovers or HEALTH_HEAP_RETRY_MS passes (the trial deadline leaves room for it).
    uint32_t until = uptime_ms() + HEALTH_HEAP_RETRY_MS;
    bool ota, ok;
    unsigned free_b, min_b;
    for (;;) {
        ota = tcp_answers(OTA_PORT);
        free_b = (unsigned) xPortGetFreeHeapSize();
        min_b = (unsigned) xPortGetMinimumEverFreeHeapSize();
        ok = ota && free_b >= HEALTH_HEAP_FREE_MIN && min_b >= HEALTH_HEAP_EVER_MIN;
        if (ok || (int32_t) (uptime_ms() - until) >= 0) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    printf("S0: %s at %lu s: ota %d, heap free %u min %u%s\n", ok ? "passed" : "FAILED",
           (unsigned long) (uptime_ms() / 1000), (int) ota, free_b, min_b,
           !ok ? " -> not confirming" : confirm_hook ? " -> confirming" : " (OTA_TEST: not confirming)");
    if (ok && confirm_hook) {
        confirm_hook();
    }
    vTaskDelete(NULL);
}

void health_start(void) {
    if (xTaskCreate(s0_task, "s0", S0_STACK_WORDS, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS) {
        printf("S0: task create failed -> not confirming\n");
    }
}

// Controller presence for "No Response" debugging: one line whenever the CASE session or subscription count
// changes (runs on every Matter loop, i.e. after each packet or timer).
static void log_peers(mt_node *n) {
    static unsigned last_case = ~0u, last_subs = ~0u;
    static uint32_t last_drops = 0;
    unsigned c = mt_node_session_count(n, MT_SESS_CASE), subs = mt_im_sub_count(&n->im);
    uint32_t drops = n->xchg.rx_no_session + n->xchg.rx_bad_mic + n->case_started + n->case_failed + n->sc_refused;
    if (c != last_case || subs != last_subs || drops != last_drops) {
        printf("matter: %lus case %u subs %u, rx dropped: no session %lu, bad mic %lu; sigma1 %lu, case failed %lu, "
               "refused %lu\n",
               (unsigned long) (uptime_ms() / 1000), c, subs, (unsigned long) n->xchg.rx_no_session,
               (unsigned long) n->xchg.rx_bad_mic, (unsigned long) n->case_started, (unsigned long) n->case_failed,
               (unsigned long) n->sc_refused);
        for (unsigned i = 0; i < MT_XCHG_N_SESSIONS; i++) {
            const mt_xchg_session *x = &n->xchg.sess[i];
            if (x->kind == MT_SESS_CASE)
                printf("matter:   case s%u fabric %u peer %08lx%08lx subs %u\n", x->local_id, x->fabric_index,
                       (unsigned long) (x->peer_node >> 32), (unsigned long) x->peer_node, x->subs);
        }
        if (last_case == ~0u)
            for (unsigned i = 0; i < MT_FABRIC_MAX; i++) {
                const mt_fabric *f = &n->fabrics.slots[i];
                if (f->index)
                    printf("matter:   fabric %u vendor %04x id %08lx%08lx node %08lx%08lx label '%s'\n", f->index,
                           f->vendor_id, (unsigned long) (f->fabric_id >> 32), (unsigned long) f->fabric_id,
                           (unsigned long) (f->node_id >> 32), (unsigned long) f->node_id, f->label);
            }
        last_case = c;
        last_subs = subs;
        last_drops = drops;
    }
}

uint32_t health_poll(mt_node *n) {
    static bool active;
    static uint32_t next;
    log_peers(n);
    bool busy = mt_root_failsafe_armed(&n->root) || mt_node_handshake_busy(n) ||
                mt_node_session_count(n, MT_SESS_PASE) > 0;
    uint32_t now = uptime_ms();
    if (!busy && !active) {
        return UINT32_MAX;
    }
    if (busy != active || mt_due(now, next)) {
        printf("matter: %s heap free %u min %u, matter stack free %u words\n",
               !busy ? "commissioning idle," : active ? "commissioning," : "commissioning started,",
               (unsigned) xPortGetFreeHeapSize(), (unsigned) xPortGetMinimumEverFreeHeapSize(),
               (unsigned) uxTaskGetStackHighWaterMark(NULL));
        active = busy;
        next = now + HEALTH_COMMISSION_LOG_MS;
    }
    return active ? next - now : UINT32_MAX;
}
