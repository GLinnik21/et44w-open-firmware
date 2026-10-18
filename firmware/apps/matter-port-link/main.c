// Link test of libs/matter-port-ambz2: the matter-base boot order with the Matter port and a node that has only
// endpoint 0. TEST attestation (public connectedhomeip DAC/PAI/CD, tools/matter-host/test_credentials.c); never
// pushed to a device.
#include <stdio.h>

#include "FreeRTOS.h"
#include "task.h"
#include "main.h"

#include "netlog.h"
#include "ota.h"
#include "ota_pubkey.h"
#include "wdog.h"

#include "matter_setup_info.h"
#include "mtp_port.h"
#include "test_credentials.h"
#include "wifi_credentials.h" // development network (git-ignored, apps/example-switch)

static const uint8_t ota_key[32] = OTA_PUBLIC_KEY_INIT;
static const uint8_t salt[] = MATTER_PBKDF_SALT;
static const uint8_t w0[] = MATTER_SPAKE2P_W0;
static const uint8_t l[] = MATTER_SPAKE2P_L;

static const mt_basic_cfg basic = {
    "ET44W-Open", MH_TEST_VID, "Port link test", MH_TEST_PID, 1, "1", 1, "0.0.1", "LINK-0001", "link-0001", 3, 3, 1,
};

static mtp_credentials cred; // filled in main: the test blobs are extern, not constant expressions

static void on_ip(void* ctx) {
    (void) ctx;
    ota_confirm();
}

static void started(void* ctx, mt_node* n) {
    (void) ctx;
    printf("[matter-port-link] node started, window %s\r\n", mt_node_window_open(n) ? "open" : "closed");
}

static mtp_app app = {
    .cred = &cred,
    .dev_ssid = WIFI_SSID,
    .dev_pass = WIFI_PASSWORD,
    .on_ip = on_ip,
    .started = started,
};

int main(void) {
    mtp_boot_capture(); // before netlog_init clears the reset reason
    netlog_init();
    ota_boot_check();
    wdog_start();
    wlan_network();
    netlog_start(NETLOG_PORT);
    ota_start(&(const ota_options) { .port = OTA_PORT, .publicKey = ota_key });

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
    app.node.boot_window_s = 0; // as the device app: the on-network window stays open while uncommissioned
    app.node.device_type = 0;
    app.node.device_name = "Port link test";
    app.node.pairing_hint = 33;
    app.node.location_cap = MT_REG_INDOOR_OUTDOOR;
    app.node.net_replace_when_full = true;
    if (!mtp_start(&app)) {
        printf("[matter-port-link] mtp_start failed\r\n");
    }
    vTaskStartScheduler();
    return 0;
}
