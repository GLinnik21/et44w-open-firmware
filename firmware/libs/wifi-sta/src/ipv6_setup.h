#pragma once

/** Turns on SLAAC and wires lwIP's IPv6 multicast groups to the Wi-Fi driver's filter. Call once
    the radio is up (the link-local address exists). A no-op without LWIP_IPV6. */
void ipv6_setup(void);
