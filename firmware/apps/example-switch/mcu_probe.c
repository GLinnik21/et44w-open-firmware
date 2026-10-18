#include "mcu_probe.h"

#include <stdio.h>

#include "tuyamcu_port.h"

static void LogDp(const tm_dp* dp) {
    printf("mcu: dp %u type %u len %u:", dp->id, dp->type, dp->len);
    for (uint16_t i = 0; i < dp->len; i++) {
        printf(" %02x", dp->data[i]);
    }
    printf("\n");
}

static void LogProduct(const uint8_t* json, size_t len) {
    printf("mcu: product "); // byte by byte: the SDK printf ignores %.*s precision
    for (size_t i = 0; i < len; i++) {
        printf("%c", json[i]);
    }
    printf("\n");
}

static void OnEvent(const tm_event* ev, void* ctx) {
    (void) ctx;
    switch (ev->type) {
        case TM_EV_LINK_UP: printf("mcu: link up\n"); break;
        case TM_EV_LINK_DOWN: printf("mcu: link down\n"); break;
        case TM_EV_PRODUCT: LogProduct(ev->data, ev->len); break;
        case TM_EV_WIFI_RESET: printf("mcu: wifi reset requested (mode 0x%02x), ignored\n", ev->arg); break;
        case TM_EV_DP: LogDp(ev->dp); break;
    }
}

void mcu_probe_start(void) {
    static const tuyamcu_port_config config = { .on_event = OnEvent };
    if (!tuyamcu_port_start(&config)) {
        printf("mcu: port start failed\n");
    }
    // The probe doesn't follow Wi-Fi or pairing, so it leaves the MCU's Wi-Fi icon at the core's initial
    // TM_NET_NO_LINK rather than claim a state it doesn't know.
}
