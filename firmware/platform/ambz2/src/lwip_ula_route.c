// Next hop for ULA destinations (fc00::/7) when the router announces itself with lifetime 0.
// Some routers send ULA-only RAs with router lifetime 0, so lwIP has no default router and can't reply
// to a controller on another ULA subnet (e.g. a Matter controller on a different segment).
// We remember the link-local source of the last valid RA (hop limit 255, link-local source, code 0:
// RFC 4861 6.1.2) and use it as the next hop for ULA destinations only, so a segment without a global
// prefix still gets no IPv6 internet route. The entry expires ROUTER_HOLD_MS after the last RA.
// lwIP also only picks a ULA source address whose /64 matches the destination, so a UDP reply
// from an unbound socket to another ULA subnet had no source and was dropped; the wrapped
// ip6_select_source_address below falls back to our own ULA address (TCP and ICMP replies
// reuse the request's destination address and never needed it).
#include "lwip_hooks.h"

#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/prot/icmp6.h"
#include "lwip/prot/ip6.h"
#include "lwip/sys.h"

#if LWIP_IPV6

#define ICMP6_TYPE_RA_ 134
#define RA_MIN_LEN     16                    // ICMPv6 header + hop limit, flags, lifetime, reachable, retrans
#define ROUTER_HOLD_MS (3u * 600u * 1000u)   // 3 x MaxRtrAdvInterval's default (RFC 4861 6.2.1)

static ip6_addr_t router;
static int have_router;
static u32_t routerSeen; // sys_now() of the last RA

int lwip_ula_route_input(struct pbuf* p, struct netif* inp) {
    (void) inp;
    if (p->len < IP6_HLEN + RA_MIN_LEN) {
        return 0;
    }
    const struct ip6_hdr* h = (const struct ip6_hdr*) p->payload;
    const u8_t* icmp = (const u8_t*) p->payload + IP6_HLEN;
    if (IP6H_NEXTH(h) != IP6_NEXTH_ICMP6 || IP6H_HOPLIM(h) != 255 || icmp[0] != ICMP6_TYPE_RA_ || icmp[1] != 0) {
        return 0;
    }
    ip6_addr_t src;
    ip6_addr_copy(src, h->src);
    if (ip6_addr_islinklocal(&src)) {
        router = src;
        routerSeen = sys_now();
        have_router = 1;
    }
    return 0; // never consumed; lwIP processes the RA as usual
}

const struct ip6_addr* lwip_ula_route_gw(struct netif* netif, const struct ip6_addr* dest) {
    (void) netif;
    if (!have_router || (lwip_ntohl(dest->addr[0]) & 0xfe000000UL) != 0xfc000000UL) {
        return NULL;
    }
    if ((u32_t) (sys_now() - routerSeen) > ROUTER_HOLD_MS) {
        have_router = 0; // no RA for too long: the router is gone or changed
        return NULL;
    }
    return &router;
}

// Linked with -Wl,--wrap=ip6_select_source_address (platform.mk).
const ip_addr_t* __real_ip6_select_source_address(struct netif* netif, const ip6_addr_t* dest);

const ip_addr_t* __wrap_ip6_select_source_address(struct netif* netif, const ip6_addr_t* dest) {
    const ip_addr_t* src = __real_ip6_select_source_address(netif, dest);
    if (src != NULL || !ip6_addr_isuniquelocal(dest)) {
        return src;
    }
    for (u8_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) && ip6_addr_isuniquelocal(netif_ip6_addr(netif, i))) {
            return netif_ip_addr6(netif, i);
        }
    }
    return NULL;
}

#endif
