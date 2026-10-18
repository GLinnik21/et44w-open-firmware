/* lwIP options for the firmware: the SDK's lwipopts.h plus our overrides.
 * Shadows component/common/api/network/include/lwipopts.h ($(d)/config comes first in sdk_INC). */
#pragma once

#include_next "lwipopts.h"

/* Sockets: sized for the removed HomeKit firmware (9 sessions + listener) and kept, plus OTA (1), netlog (2), web
 * page (2: listener + client), mDNS (raw UDP pcb) and room for SNTP/provisioning. The web server closes first, so each page poll
 * leaves a TCP PCB in TIME_WAIT (lwIP reuses those first when PCBs run out). */
#undef  MEMP_NUM_NETCONN
#define MEMP_NUM_NETCONN        18
#undef  MEMP_NUM_TCP_PCB
#define MEMP_NUM_TCP_PCB        16
#undef  MEMP_NUM_UDP_PCB
#define MEMP_NUM_UDP_PCB        12 /* DHCP, mDNS v4+v6, SNTP, DNS (random source port per query) ... */

/* Rebind listeners right after a restart (TIME_WAIT). */
#undef  SO_REUSE
#define SO_REUSE                1

/* Dual stack: IPv4 + IPv6 (SLAAC, link-local). */
#undef  LWIP_IPV6
#define LWIP_IPV6               1
#define LWIP_IPV6_MLD           1
#define LWIP_IPV6_AUTOCONFIG    1
#define LWIP_ICMP6              1

/* Source mDNS responder (src/apps/mdns), replaces the prebuilt lib_mdns. */
#define LWIP_MDNS_RESPONDER     1
#undef  LWIP_NUM_NETIF_CLIENT_DATA
#define LWIP_NUM_NETIF_CLIENT_DATA 1
#undef  LWIP_IGMP
#define LWIP_IGMP               1
#undef  MEMP_NUM_SYS_TIMEOUT
#define MEMP_NUM_SYS_TIMEOUT    24

/* IPv6 next hop for ULA destinations despite a lifetime-0 RA (src/lwip_ula_route.c). */
#define LWIP_HOOK_FILENAME      "lwip_hooks.h"
