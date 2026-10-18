/* Matter's UDP endpoint: one dual-stack socket on [::]:5540 (lwIP 2.0.2 binds IP6_ADDR_ANY with v6only off to
 * IP_ANY_TYPE, reports IPv4 peers as v4-mapped addresses and unmaps them again on sendto).
 *
 * RX: a small task blocks in recvfrom into one of MTP_UDP_SLOTS static buffers and posts the slot to the Matter
 * task, which releases it after mt_node_on_udp. With every slot busy the task waits (lwIP keeps queueing in the
 * socket's mailbox and drops beyond it; MRP retransmits).
 * TX: sendto from the Matter task (lwIP allows send and a blocked recv on one socket from two threads). There is no
 * IPV6_PKTINFO in this lwIP: the source address is lwIP's choice (ip6_select_source_address for IPv6, the netif
 * address for IPv4), which is right with a single interface.
 * Addresses: mt_node_addr.family 4 = IPv4 in ip[0..3], 6 = IPv6 (scope = sin6_scope_id, unused by lwIP 2.0.2). */
#include <string.h>

#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"

#include "lwip/sockets.h"
#include "wifi_conf.h"

#include "port.h"

#define RX_STACK_WORDS 384
#define RX_PRIORITY (tskIDLE_PRIORITY + 2)

static mtp_rx_slot slots[MTP_UDP_SLOTS];
static volatile uint8_t slot_busy;      /* bit per slot; written under the critical section */
static SemaphoreHandle_t free_slots;
static volatile int sock = -1;

static const uint8_t v4_mapped_prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };

static void addr_from(mt_node_addr *a, const struct sockaddr_in6 *s)
{
    memset(a, 0, sizeof *a);
    a->port = ntohs(s->sin6_port);
    if (!memcmp(&s->sin6_addr, v4_mapped_prefix, sizeof v4_mapped_prefix)) {
        a->family = 4;
        memcpy(a->ip, (const uint8_t *)&s->sin6_addr + 12, 4);
    } else {
        a->family = 6;
        memcpy(a->ip, &s->sin6_addr, 16);
        a->scope = s->sin6_scope_id;
    }
}

static int open_socket(void)
{
    struct sockaddr_in6 any;
    int s = lwip_socket(AF_INET6, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    memset(&any, 0, sizeof any);
    any.sin6_len = sizeof any;
    any.sin6_family = AF_INET6;
    any.sin6_port = htons(MTP_UDP_PORT);   /* sin6_addr all zero = in6addr_any, dual-stack */
    if (lwip_bind(s, (struct sockaddr *)&any, sizeof any) < 0) {
        lwip_close(s);
        return -1;
    }
    return s;
}

/* Trace for "No Response" debugging: one line per received datagram (source, session id, length) and every
 * failed send. Off with -DMTP_UDP_TRACE=0. */
#ifndef MTP_UDP_TRACE
#define MTP_UDP_TRACE 0
#endif

static void log_addr(const char *what, const struct sockaddr_in6 *a, int len, const uint8_t *p)
{
    const uint8_t *b = (const uint8_t *)&a->sin6_addr;
    MTP_LOG("udp %lu: %s %02x%02x:%02x%02x..%02x%02x:%02x%02x port %u len %d sess %u\r\n", (unsigned long)mtp_now_ms(NULL), what, b[0], b[1], b[2], b[3], b[12],
            b[13], b[14], b[15], ntohs(a->sin6_port), len, len >= 3 ? (unsigned)(p[1] | p[2] << 8) : 0u);
}

static int take_slot(void)
{
    int i = -1;
    xSemaphoreTake(free_slots, portMAX_DELAY);
    taskENTER_CRITICAL();
    for (unsigned k = 0; k < MTP_UDP_SLOTS; k++)
        if (!(slot_busy & (1u << k))) { slot_busy |= (uint8_t)(1u << k); i = (int)k; break; }
    taskEXIT_CRITICAL();
    return i;
}

static void rx_task(void *arg)
{
    (void)arg;
    while (!wifi_is_up(RTW_STA_INTERFACE)) vTaskDelay(pdMS_TO_TICKS(200));   /* lwIP and the netif are up */
    while ((sock = open_socket()) < 0) {
        MTP_LOG("udp: bind [::]:%u failed, retrying\r\n", MTP_UDP_PORT);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    MTP_LOG("udp: listening on [::]:%u\r\n", MTP_UDP_PORT);
    for (;;) {
        int i = take_slot();
        struct sockaddr_in6 from;
        socklen_t flen = sizeof from;
        int n;
        if (i < 0) continue;   /* cannot happen: the semaphore counts free slots */
        n = lwip_recvfrom(sock, slots[i].buf, sizeof slots[i].buf, 0, (struct sockaddr *)&from, &flen);
        if (n <= 0 || flen < sizeof from || from.sin6_family != AF_INET6) {
            mtp_udp_release((uint8_t)i);
            if (n < 0) vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        if (MTP_UDP_TRACE) log_addr("rx", &from, n, slots[i].buf);
        addr_from(&slots[i].from, &from);
        slots[i].len = (uint16_t)n;
        if (!mtp_post(&(const mtp_event){ .kind = MTP_EV_RX, .slot = (uint8_t)i })) mtp_udp_release((uint8_t)i);
    }
}

bool mtp_udp_bound(void) { return sock >= 0; }

bool mtp_udp_start(void)
{
    free_slots = xSemaphoreCreateCounting(MTP_UDP_SLOTS, MTP_UDP_SLOTS);
    if (!free_slots) return false;
    return xTaskCreate(rx_task, "mt_rx", RX_STACK_WORDS, NULL, RX_PRIORITY, NULL) == pdPASS;
}

mtp_rx_slot *mtp_udp_slot(uint8_t slot) { return slot < MTP_UDP_SLOTS ? &slots[slot] : NULL; }

void mtp_udp_release(uint8_t slot)
{
    if (slot >= MTP_UDP_SLOTS) return;
    taskENTER_CRITICAL();
    slot_busy &= (uint8_t)~(1u << slot);
    taskEXIT_CRITICAL();
    xSemaphoreGive(free_slots);
}

void mtp_udp_send(void *ctx, const mt_node_addr *to, mt_span frame)
{
    struct sockaddr_in6 dst;
    (void)ctx;
    if (sock < 0 || !to || (to->family != 4 && to->family != 6)) return;
    memset(&dst, 0, sizeof dst);
    dst.sin6_len = sizeof dst;
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons(to->port);
    if (to->family == 4) {
        memcpy(&dst.sin6_addr, v4_mapped_prefix, sizeof v4_mapped_prefix);
        memcpy((uint8_t *)&dst.sin6_addr + 12, to->ip, 4);
    } else {
        memcpy(&dst.sin6_addr, to->ip, 16);
        dst.sin6_scope_id = to->scope;
    }
    /* best effort: MRP retransmits */
    if (lwip_sendto(sock, frame.p, frame.len, 0, (const struct sockaddr *)&dst, sizeof dst) < 0)
        log_addr("send failed to", &dst, (int)frame.len, frame.p);
    else if (MTP_UDP_TRACE)
        log_addr("tx", &dst, (int)frame.len, frame.p);
}
