// IPv6 bits the Realtek lwIP 2.0.2 port leaves out: SLAAC is off, and IPv6 multicast groups are
// never registered with the Wi-Fi driver's multicast filter (no mld_mac_filter), so neighbor
// solicitations to our solicited-node group, and ff02::fb mDNS, never reach lwIP.
#include "ipv6_setup.h"

#include "lwip/mld6.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip_netconf.h"
#include "wifi_conf.h"

#include <stdio.h>

#if LWIP_IPV6

static err_t mac_filter(struct netif* netif, const ip6_addr_t* group, enum netif_mac_filter_action action) {
    (void) netif;
    // RFC 2464: 33:33 + the low 32 bits of the group address.
    uint32_t low = lwip_ntohl(group->addr[3]);
    rtw_mac_t mac = { { 0x33, 0x33, (uint8_t) (low >> 24), (uint8_t) (low >> 16), (uint8_t) (low >> 8),
                        (uint8_t) low } };
    int rc = action == NETIF_ADD_MAC_FILTER ? wifi_register_multicast_address(&mac)
                                            : wifi_unregister_multicast_address(&mac);
    printf("ipv6: %s multicast %02x:%02x:%02x:%02x:%02x:%02x -> %d\r\n", action == NETIF_ADD_MAC_FILTER ? "add" : "del",
           mac.octet[0], mac.octet[1], mac.octet[2], mac.octet[3], mac.octet[4], mac.octet[5], rc);
    return rc == 0 ? ERR_OK : ERR_IF;
}

static void install(void* arg) {
    struct netif* netif = arg;
    netif_set_ip6_autoconfig_enabled(netif, 1);
    netif->flags |= NETIF_FLAG_MLD6;
    netif_set_mld_mac_filter(netif, mac_filter);
    // Groups joined before now (the link-local's solicited-node) never went through
    // the hook; lwIP only calls it when a group is first created.
    for (struct mld_group* g = netif_mld6_data(netif); g != NULL; g = g->next) {
        mac_filter(netif, &g->group_address, NETIF_ADD_MAC_FILTER);
    }
    // All-nodes (RAs, neighbor advertisements) is not an MLD group in this port.
    mac_filter(netif, &(const ip6_addr_t) { { PP_HTONL(0xff020000UL), 0, 0, PP_HTONL(1) } }, NETIF_ADD_MAC_FILTER);
}

void ipv6_setup(void) {
    tcpip_callback(install, &xnetif[0]);
}

#else

void ipv6_setup(void) {}

#endif
