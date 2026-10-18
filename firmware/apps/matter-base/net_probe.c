// Measurement: is IoT -> Home reachable over IPv6 (and, as a control, IPv4)? Waits for a routable IPv6
// address (SLAAC), logs it, then tries a TCP connect to each target. "connected" or "refused" means
// the router forwarded the SYN; "timeout" means it was dropped. Targets: net_probe_targets.h.
#include "net_probe.h"
#include "net_probe_targets.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "lwip_netconf.h"

#define ADDR_WAIT_S       90
#define CONNECT_TIMEOUT_S 8

static bool has_routable_v6(void) {
    bool found = false;
    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        const ip6_addr_t* a = netif_ip6_addr(&xnetif[0], i);
        if (ip6_addr_isvalid(netif_ip6_addr_state(&xnetif[0], i)) && !ip6_addr_islinklocal(a)) {
            found = true;
        }
    }
    return found;
}

static void log_v6(void) {
    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        u8_t state = netif_ip6_addr_state(&xnetif[0], i);
        if (!ip6_addr_isinvalid(state)) {
            printf("[net_probe] ip6[%d] %s state 0x%x\r\n", i, ip6addr_ntoa(netif_ip6_addr(&xnetif[0], i)), state);
        }
    }
}

static const char* try_connect(int family, const char* host, uint16_t port) {
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t len;
    if (family == AF_INET6) {
        struct sockaddr_in6* a = (struct sockaddr_in6*) &ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port);
        if (!inet_pton(AF_INET6, host, &a->sin6_addr)) {
            return "bad address";
        }
        len = sizeof *a;
    } else {
        struct sockaddr_in* a = (struct sockaddr_in*) &ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(port);
        if (!inet_pton(AF_INET, host, &a->sin_addr)) {
            return "bad address";
        }
        len = sizeof *a;
    }
    int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return "no socket";
    }
    int on = 1;
    ioctlsocket(fd, FIONBIO, &on);
    // Non-blocking connect, then wait for writable and read SO_ERROR: doesn't depend on errno,
    // which this lwIP port doesn't set reliably.
    connect(fd, (struct sockaddr*) &ss, len);
    fd_set w;
    FD_ZERO(&w);
    FD_SET(fd, &w);
    struct timeval tv = { .tv_sec = CONNECT_TIMEOUT_S };
    const char* result;
    if (select(fd + 1, NULL, &w, NULL, &tv) <= 0) {
        result = "timeout";
    } else {
        int err = 0;
        socklen_t el = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
        static char buf[24];
        snprintf(buf, sizeof buf, err == 0 ? "connected" : err == ECONNREFUSED ? "refused" : "error %d", err);
        result = buf;
    }
    close(fd);
    return result;
}

static void probe_task(void* arg) {
    (void) arg;
    for (int s = 0; s < ADDR_WAIT_S && !has_routable_v6(); s++) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    for (int round = 0; round < 3; round++) {
        log_v6();
        static const char* const v6_targets[] = { NET_PROBE_V6_TARGETS };
        for (unsigned i = 0; i < sizeof v6_targets / sizeof v6_targets[0]; i++) {
            printf("[net_probe] IoT->Home v6 [%s]:%u %s\r\n", v6_targets[i], NET_PROBE_PORT,
                   try_connect(AF_INET6, v6_targets[i], NET_PROBE_PORT));
        }
        printf("[net_probe] IoT->Home v4 %s:%u %s (control, ACL should drop)\r\n", NET_PROBE_V4_TARGET,
               NET_PROBE_PORT, try_connect(AF_INET, NET_PROBE_V4_TARGET, NET_PROBE_PORT));
        vTaskDelay(pdMS_TO_TICKS(60 * 1000));
    }
    printf("[net_probe] done; this build never confirms, the OTA trial rolls back\r\n");
    vTaskDelete(NULL);
}

void net_probe_start(void) {
    xTaskCreate(probe_task, "net_probe", 512, NULL, tskIDLE_PRIORITY + 1, NULL);
}
