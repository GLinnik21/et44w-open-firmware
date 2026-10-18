/* lwIP hooks (LWIP_HOOK_FILENAME, set in lwipopts.h). Implemented in src/lwip_ula_route.c. */
#pragma once

#include "lwip/arch.h"

struct pbuf;
struct netif;
struct ip6_addr;

int lwip_ula_route_input(struct pbuf* p, struct netif* inp);
const struct ip6_addr* lwip_ula_route_gw(struct netif* netif, const struct ip6_addr* dest);

#define LWIP_HOOK_IP6_INPUT(pbuf, input_netif) lwip_ula_route_input((pbuf), (input_netif))
#define LWIP_HOOK_ND6_GET_GW(netif, dest)      lwip_ula_route_gw((netif), (dest))
