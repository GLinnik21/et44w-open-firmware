// Boot wiring only: console, network log, OTA, watchdog, then the TuyaMCU
// link, the self-check and the Matter port. mtp_start starts Wi-Fi on these development credentials at once, before
// and independent of the Matter store and node; the port's task then opens the store (60 s later after a watchdog
// reset), applies the safe-mode policy (3 watchdog resets without 5 minutes of uptime skip the node) and switches
// to a stored WIFI network if there is one. OTA and netlog never depend on Matter.
#include <stdio.h>

#include "FreeRTOS.h"
#include "task.h"
#include "main.h"

#include "clock.h"
#include "health.h"
#include "matter_config.h"
#include "mt_thermostat.h"
#include "mtp_port.h"
#include "netlog.h"
#include "ota.h"
#include "ota_pubkey.h"
#include "ota_test.h"
#include "test_credentials.h" // TEST attestation: public connectedhomeip DAC/PAI/CD (VID 0xFFF1, PID 0x8000)
#include "thermo_link.h"
#include "unit.h"             // units/<UNIT>: THERMOSTAT_NAME
#include "wdog.h"
#include "web.h"              // settings page on port 80

#include "matter_unit.h"   // units/<UNIT>, generated (lib.mk checks it exists)
#if __has_include("wifi_credentials.h")
#include "wifi_credentials.h"
#else
#error "Missing wifi_credentials.h: copy wifi_credentials.h.example and fill in WIFI_SSID and WIFI_PASSWORD"
#endif

_Static_assert(MATTER_VENDOR_ID == MH_TEST_VID && MATTER_PRODUCT_ID == MH_TEST_PID,
               "matter_unit.h VID/PID must match the attestation credentials");

static const uint8_t ota_key[32] = OTA_PUBLIC_KEY_INIT;
static const uint8_t salt[] = MATTER_PBKDF_SALT;
static const uint8_t w0[] = MATTER_SPAKE2P_W0;
static const uint8_t l[] = MATTER_SPAKE2P_L;
_Static_assert(sizeof salt == MATTER_PBKDF_SALT_LEN && sizeof salt >= 16 && sizeof salt <= 32, "matter_unit.h salt");
_Static_assert(sizeof w0 == 32 && sizeof l == 65, "matter_unit.h verifier");

static const mt_basic_cfg basic = {
    TM_VENDOR_NAME, MATTER_VENDOR_ID, TM_PRODUCT_NAME, MATTER_PRODUCT_ID, TM_HW_VERSION, TM_HW_VERSION_STR,
    TM_SW_VERSION, TM_SW_VERSION_STR, MATTER_SERIAL_NUMBER, MATTER_UNIQUE_ID, 3, 3, 1,
};

static mtp_credentials cred; // filled in main: the test blobs are extern, not constant expressions

static void on_ip(void *ctx) {
    (void) ctx;
    health_on_ip();
    clock_start(); // SNTP for the MCU's schedule; idempotent
}

static void started(void *ctx, mt_node *n) {
    (void) ctx;
    printf("[thermostat-matter] node up, %u fabric(s), window %s\n", mt_fabric_committed_count(&n->fabrics),
           mt_node_window_open(n) ? "open" : "closed");
    thermo_link_started(n);
}

static uint32_t poll(void *ctx, mt_node *n) {
    (void) ctx;
    uint32_t a = thermo_link_poll(n), b = health_poll(n);
    return a < b ? a : b;
}

static mtp_app app = {
    .cred = &cred,
    .dev_ssid = WIFI_SSID,
    .dev_pass = WIFI_PASSWORD,
    .dev_rescue = true,                      // Wi-Fi comes from commissioning; WIFI_SSID only if that can't happen
    .on_ip = on_ip,
    .started = started,
    .poll = poll,
};

int main(void) {
    mtp_boot_capture();                      // before netlog_init clears the reset reason
    netlog_init();                           // tee the console into the network log
    ota_boot_check();                        // may roll back to the previous image
    wdog_start();                            // faults and CPU hogs reset, so trial boots and safe mode count them
    wlan_network();                          // LwIP + radio on (SDK)
    netlog_start(NETLOG_PORT);
    ota_start(&(const ota_options) { .port = OTA_PORT, .publicKey = ota_key });
    ota_test_start();                        // no-op unless built with OTA_TEST
    health_start();                          // S0 self-check -> ota confirm

    cred.dac = mh_test_creds.dac;
    cred.pai = mh_test_creds.pai;
    cred.cd = mh_test_creds.cd;
    cred.dac_priv = mh_test_creds.dac_priv;
    cred.vendor_id = mh_test_creds.vid;
    cred.product_id = mh_test_creds.pid;
    cred.w0 = w0;
    cred.l = l;
    cred.salt = mt_span_of(salt, sizeof salt);
    cred.iterations = MATTER_PBKDF_ITERATIONS;
    cred.discriminator = MATTER_DISCRIMINATOR;
    app.node.basic = &basic;
    app.node.boot_window_s = 0;              // on-network window open while uncommissioned
    app.node.ble_window_s = BLE_WINDOW_S;    // BLE for the first part of it, then off
                                             // until a reboot
    app.node.device_type = MT_THERMOSTAT_DEVICE_TYPE;
    app.node.device_name = THERMOSTAT_NAME;
    app.node.pairing_hint = 33;              // power cycle + device manual (chip's default)
    app.node.location_cap = MT_REG_INDOOR_OUTDOOR; // as matter-host (proven with matter.js); Apple sends SetRegulatoryConfig
    app.node.net_replace_when_full = true;

    bool linked = thermo_link_start();
    web_start(THERMOSTAT_NAME, TM_SW_VERSION_STR);
    if (linked) {
        app.node.extra_eps = thermo_link_endpoints(&app.node.n_extra_eps);
    } else {
        printf("[thermostat-matter] thermo link failed: no thermostat endpoint\n"); // S0 then fails: rollback
    }
    if (!mtp_start(&app)) {                  // starts Wi-Fi first in any case: OTA and netlog stay reachable
        printf("[thermostat-matter] mtp_start failed: Wi-Fi only, no Matter\n"); // S0 then fails: rollback
    }
    vTaskStartScheduler();
    return 0;
}
