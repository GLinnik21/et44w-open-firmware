// Measurement build: example-switch boot wiring minus HAP. Wi-Fi, OTA, watchdog, network log, TuyaMCU,
// and (with BT=1) the BLE probe. With BT, an OTA trial is confirmed only once Wi-Fi has an IPv4 address (the
// non-BT check) and the BLE cycle has finished with the heap intact and the OTA listener still answering,
// in either order; otherwise it rolls back.
#include <stdio.h>

#include "FreeRTOS.h"
#include "task.h"
#include "main.h"

#include "mcu_probe.h"
#include "netlog.h"
#include "ota.h"
#include "ota_pubkey.h"
#include "wdog.h"
#include "wifi_sta.h"
#ifdef BLE_PROBE
#include "ble_probe.h"
#endif
#include "wifi_credentials.h"
#ifdef BLE_PROBE
#include "selfcheck.h"
#endif
#ifdef NET_PROBE
#include "net_probe.h"
#endif
#ifdef CRYPTO_LINK
#include "crypto_link.h"
#endif


static const uint8_t ota_key[32] = OTA_PUBLIC_KEY_INIT;
#ifdef BLE_PROBE
static volatile bool got_ip, probe_ok; // set by the Wi-Fi and the BLE task; whichever comes second confirms
#ifdef NET_PROBE
#define CONFIRMS false // the reachability probe build never confirms: its trial rolls back
#else
#define CONFIRMS true
#endif
static void try_confirm(void)
{
    if (CONFIRMS && got_ip && probe_ok) {
        ota_confirm();
    }
}
static void on_ip(void)
{
    got_ip = true;
    try_confirm();
}
static void probe_done(bool heap_ok)
{
    bool ota_ok = selfcheck_tcp_answers(OTA_PORT); // loopback: proves the listener, not the network
    printf("[matter-base] probe done: heap %s, OTA listener %s, IP %s -> %s\r\n", heap_ok ? "ok" : "LEAKED",
           ota_ok ? "answers" : "DEAD", got_ip ? "yes" : "not yet",
           !CONFIRMS                ? "not confirming (NET_PROBE build)"
           : !(heap_ok && ota_ok)   ? "not confirming (will roll back)"
           : got_ip                 ? "confirming"
                                    : "confirming on IP");
    probe_ok = heap_ok && ota_ok;
    try_confirm();
}
#elif defined(NET_PROBE)
static void on_ip(void) {} // never confirms: the trial rolls back to the previous image
#else
static void on_ip(void) { ota_confirm(); }
#endif
static const wifi_sta_config wifi = { .ssid = WIFI_SSID, .password = WIFI_PASSWORD, .onIP = on_ip };

int main(void)
{
    netlog_init();
    ota_boot_check();
    wdog_start();
    wlan_network();
    netlog_start(NETLOG_PORT);
    ota_start(&(const ota_options) { .port = OTA_PORT, .publicKey = ota_key });
    mcu_probe_start();
    wifi_sta_start(&wifi);
#ifdef BLE_PROBE
    ble_probe_start(probe_done);
#endif
#ifdef NET_PROBE
    net_probe_start();
#endif
#ifdef CRYPTO_LINK
    crypto_link_keep(); // apps/matter-cryptolink: keeps the referenced mbedtls code in the image
#endif
    vTaskStartScheduler();
    return 0;
}
