/* The node's mDNS record set (mt_node_mdns_*) on lwIP 2.0.2's own responder (platform lwip_mdns; this lib raises
 * MDNS_MAX_SERVICES to MTP_MDNS_MAX for it under MATTER=1).
 *
 * Host name: the 12 upper-case hex digits of the MAC (Matter spec 4.3.4). Services: _matterc._udp (commissionable)
 * and _matter._tcp (one per fabric), port 5540, TTL MTP_MSUB_TTL_S (120 s, like the HAP PAL).
 *
 * Subtypes (_L<disc>, _S<short>, _V<vid>, _CM, _I<CFID>): lwIP 2.0.2 has none, so mdns_sub.c answers their PTR
 * questions. It sits in front of lwIP's receive callback on the same UDP pcb (found in udp_pcbs after
 * mdns_resp_init), answers, then hands the packet on unchanged; no vendor edit, no second socket on 5353.
 * SRV / TXT / A of the instance are lwIP's. Gap: no service removal, every change rebuilds the whole set
 * (remove_netif + add_netif + add_service), as the HAP PAL does. lwIP sends no goodbyes either, so a rebuild first
 * sends TTL-0 PTRs (service + subtypes) for the instances that went away (an old commissioning window otherwise
 * stayed in iOS's list as a second tile).
 *
 * Threads: the Matter task packs the records into `staged` (mutex) and posts one rebuild to the tcpip thread,
 * which copies staged -> live and re-registers; lwIP's TXT callback reads `live` on the tcpip thread only. */
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "semphr.h"

#include "lwip/apps/mdns.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/udp.h"

#include "mdns_sub.h"

#include "port.h"

extern struct netif xnetif[];

#define MTP_MDNS_MAX MT_NODE_MDNS_MAX
_Static_assert(MTP_MDNS_MAX <= 5, "raise MDNS_MAX_SERVICES in lib.mk");
#define TXT_BYTES 192                     /* packed [len][key=value]... per record */

typedef struct {
    bool operational;
    char instance[34];
    uint8_t n_sub;
    char sub[MT_NODE_MDNS_SUB_MAX][20];
    uint8_t txt_len;
    uint8_t txt[TXT_BYTES];
} rec;

typedef struct {
    uint8_t n;
    rec r[MTP_MDNS_MAX];
} recset;

static recset staged, live;
static mtp_msub_ent subs[MTP_MDNS_MAX * MT_NODE_MDNS_SUB_MAX];   /* point into `live`; tcpip thread only */
static unsigned n_subs;
static struct udp_pcb *mpcb;              /* lwIP's responder socket, hooked by hook_responder */
static udp_recv_fn lwip_recv;
static void *lwip_arg;
static uint8_t in_buf[1024], out_buf[768];   /* tcpip thread only */
static SemaphoreHandle_t lock;
static volatile bool posted;              /* a rebuild is queued on the tcpip thread */
static volatile bool net_up;              /* the first IPv4 address arrived: tcpip thread and MAC are there */
static bool started, registered;
static char host[13];

#define MDNS_PORT 5353

static void send_to(struct udp_pcb *pcb, struct netif *nif, const uint8_t *b, size_t len, const ip_addr_t *to,
                    u16_t port)
{
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
    if (!p) return;
    memcpy(p->payload, b, len);
    udp_sendto_if(pcb, p, to, port, nif);
    pbuf_free(p);
}

static const ip_addr_t *group(bool v6)
{
    static const ip_addr_t g4 = IPADDR4_INIT_BYTES(224, 0, 0, 251);
#if LWIP_IPV6
    static const ip_addr_t g6 = IPADDR6_INIT_HOST(0xFF020000, 0, 0, 0xFB);
    if (v6) return &g6;
#else
    (void)v6;
#endif
    return &g4;
}

/* out_buf (len bytes) to both mDNS groups. */
static void send_groups(struct netif *nif, size_t len)
{
    send_to(mpcb, nif, out_buf, len, group(false), MDNS_PORT);
#if LWIP_IPV6
    send_to(mpcb, nif, out_buf, len, group(true), MDNS_PORT);
#endif
}

/* A query with questions (header only): most mDNS traffic is responses, which mtp_msub_reply ignores anyway. */
static bool is_query(struct pbuf *p)
{
    uint8_t h[12];
    return pbuf_copy_partial(p, h, sizeof h, 0) == sizeof h && !(h[2] & 0xF8) && (h[4] | h[5]);
}

/* In front of lwIP's receive callback: answer subtype questions, then pass the packet on (it frees it). */
static void sub_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    struct netif *nif = ip_current_input_netif();
    if (registered && n_subs && nif == &xnetif[0] && p->tot_len >= 12 && p->tot_len <= sizeof in_buf &&
        is_query(p) && pbuf_copy_partial(p, in_buf, p->tot_len, 0) == p->tot_len) {
        bool uni;
        size_t n = mtp_msub_reply(in_buf, p->tot_len, port != MDNS_PORT, subs, n_subs, out_buf, sizeof out_buf,
                                  &uni);
        if (n) send_to(pcb, nif, out_buf, n, uni ? addr : group(IP_IS_V6(addr)), uni ? port : MDNS_PORT);
    }
    lwip_recv(lwip_arg, pcb, p, addr, port);
    (void)arg;
}

static void hook_responder(void)
{
    for (struct udp_pcb *p = udp_pcbs; p; p = p->next)
        if (p->local_port == MDNS_PORT && p->recv && p->recv != sub_recv) {
            lwip_recv = p->recv;
            lwip_arg = p->recv_arg;
            mpcb = p;
            udp_recv(p, sub_recv, NULL);
            return;
        }
    MTP_LOG("mdns: responder pcb not found, no subtypes\r\n");
}

/* The subtype table over `live`, then one unsolicited announcement of it (lwIP announces the rest). */
static void publish_subtypes(struct netif *nif)
{
    size_t n;
    n_subs = 0;
    if (!mpcb) return;
    for (unsigned i = 0; i < live.n; i++)
        for (unsigned j = 0; j < live.r[i].n_sub && n_subs < sizeof subs / sizeof subs[0]; j++) {
            subs[n_subs].sub = live.r[i].sub[j];
            subs[n_subs].instance = live.r[i].instance;
            subs[n_subs].operational = live.r[i].operational;
            n_subs++;
        }
    n = mtp_msub_announce(subs, n_subs, out_buf, sizeof out_buf);
    if (n) send_groups(nif, n);
}

static void get_txt(struct mdns_service *svc, void *userdata)
{
    const rec *r = userdata;
    for (unsigned i = 0; i < r->txt_len; i += 1u + r->txt[i])
        if (mdns_resp_add_service_txtitem(svc, (const char *)&r->txt[i + 1], r->txt[i]) != ERR_OK) return;
}

static bool in_set(const recset *s, const rec *r)
{
    for (unsigned i = 0; i < s->n; i++)
        if (s->r[i].operational == r->operational && !strcmp(s->r[i].instance, r->instance)) return true;
    return false;
}

/* Goodbye for the records of `live` that `next` no longer has; built before live is replaced. */
static void say_goodbye(struct netif *nif, const recset *next)
{
    static mtp_msub_ent gone[MTP_MSUB_MAX];   /* tcpip thread only */
    unsigned n = 0;
    size_t len;
    if (!mpcb || !registered) return;
    for (unsigned i = 0; i < live.n; i++) {
        const rec *r = &live.r[i];
        if (in_set(next, r)) continue;
        for (int j = -1; j < (int)r->n_sub && n < MTP_MSUB_MAX; j++)
            gone[n++] = (mtp_msub_ent){ .sub = j < 0 ? NULL : r->sub[j], .instance = r->instance,
                                        .operational = r->operational };
    }
    len = mtp_msub_goodbye(gone, n, out_buf, sizeof out_buf);
    if (len) send_groups(nif, len);
}

static void stop(struct netif *nif)
{
    if (registered) mdns_resp_remove_netif(nif);
    registered = false;
    n_subs = 0;
}

static void rebuild(void *arg)
{
    struct netif *nif = &xnetif[0];
    err_t err;
    (void)arg;
    posted = false;
    xSemaphoreTake(lock, portMAX_DELAY);
    say_goodbye(nif, &staged);
    live = staged;
    xSemaphoreGive(lock);
    if (!started) {
        mdns_resp_init();
        hook_responder();
        started = true;
    }
    stop(nif);
    if (!live.n) return;
    nif->flags |= NETIF_FLAG_IGMP;   /* needed to join the mDNS groups (as in the HAP PAL) */
#if LWIP_IPV6
    nif->flags |= NETIF_FLAG_MLD6;
#endif
    if (!host[0]) {
        const uint8_t *m = nif->hwaddr;
        if (!(m[0] | m[1] | m[2] | m[3] | m[4] | m[5])) {
            MTP_LOG("mdns: no MAC yet\r\n");
            return;
        }
        snprintf(host, sizeof host, "%02X%02X%02X%02X%02X%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
    }
    err = mdns_resp_add_netif(nif, host, MTP_MSUB_TTL_S);
    if (err != ERR_OK) {
        MTP_LOG("mdns: add_netif %d\r\n", (int)err);
        return;
    }
    registered = true;
    for (unsigned i = 0; i < live.n; i++) {
        rec *r = &live.r[i];
        err = mdns_resp_add_service(nif, r->instance, r->operational ? "_matter" : "_matterc",
                                    r->operational ? DNSSD_PROTO_TCP : DNSSD_PROTO_UDP, MTP_UDP_PORT, MTP_MSUB_TTL_S,
                                    get_txt, r);
        if (err != ERR_OK) MTP_LOG("mdns: add_service %s %d\r\n", r->instance, (int)err);
    }
    publish_subtypes(nif);
}

static void post(void)
{
    if (posted) return;
    posted = true;
    if (tcpip_callback(rebuild, NULL) != ERR_OK) {
        posted = false;
        MTP_LOG("mdns: tcpip_callback failed\r\n");
    }
}

static void pack(rec *out, const mt_node_mdns_rec *in)
{
    unsigned used = 0;
    out->operational = in->operational;
    memcpy(out->instance, in->instance, sizeof out->instance);
    out->instance[sizeof out->instance - 1] = 0;
    out->n_sub = 0;
    for (unsigned i = 0; i < in->n_sub && i < MT_NODE_MDNS_SUB_MAX; i++) {
        memcpy(out->sub[out->n_sub], in->sub[i], sizeof out->sub[0]);
        out->sub[out->n_sub++][sizeof out->sub[0] - 1] = 0;
    }
    for (unsigned i = 0; i < in->n_txt && i < MT_NODE_MDNS_TXT_MAX; i++) {
        size_t n = strnlen(in->txt[i], sizeof in->txt[i]);
        if (used + 1 + n > TXT_BYTES) {
            MTP_LOG("mdns: TXT of %s truncated\r\n", out->instance);
            break;
        }
        out->txt[used] = (uint8_t)n;
        memcpy(&out->txt[used + 1], in->txt[i], n);
        used += 1 + (unsigned)n;
    }
    out->txt_len = (uint8_t)used;
}

void mtp_mdns_changed(void *ctx)
{
    const mt_node *n = ctx;
    static mt_node_mdns_rec tmp;   /* Matter task only */
    unsigned count = mt_node_mdns_count(n);
    if (!lock && !(lock = xSemaphoreCreateMutex())) return;
    xSemaphoreTake(lock, portMAX_DELAY);
    staged.n = 0;
    for (unsigned i = 0; i < count && staged.n < MTP_MDNS_MAX; i++)
        if (mt_node_mdns_get(n, i, &tmp)) pack(&staged.r[staged.n++], &tmp);
    xSemaphoreGive(lock);
    if (net_up) post();   /* before that, mtp_mdns_restart publishes what is staged */
}

void mtp_mdns_restart(void)
{
    net_up = true;
    if (lock) post();     /* nothing to announce before the first mtp_mdns_changed */
}
