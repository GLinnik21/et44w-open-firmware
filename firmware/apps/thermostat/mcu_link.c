#include "HAP.h" // first: thermostat.h pulls it in, and it must precede libc headers

#include "mcu_link.h"

#include <stdio.h>

#include "dp_cache.h"
#include "thermo_mcu.h"
#include "thermostat.h"
#include "tuyamcu_port.h"

static void OnEvent(const tm_event* ev, void* ctx) {
    (void) ctx;
    switch (ev->type) {
        case TM_EV_LINK_UP: printf("mcu: link up\n"); break;
        case TM_EV_LINK_DOWN: printf("mcu: link down\n"); break;
        case TM_EV_PRODUCT: printf("mcu: product info %u bytes\n", (unsigned) ev->len); break;
        case TM_EV_WIFI_RESET: printf("mcu: wifi reset requested (mode %u), not supported yet\n", ev->arg); break;
        case TM_EV_DP:
            dp_cache_put(ev->dp);
            int32_t value;
            if (thermo_mcu_report(ev->dp, &value)) {
                thermostat_post_report(ev->dp->id, value);
            }
            break;
    }
}

bool mcu_link_start(void) {
    static const tuyamcu_port_config config = { .on_event = OnEvent, .get_time = thermo_mcu_time };
    return tuyamcu_port_start(&config);
}
