// Boot wiring only: console, network log, OTA, watchdog, Wi-Fi, HAP task, MCU link, scheduler.
#include "FreeRTOS.h"
#include "task.h"
#include "main.h"

#include "accessory.h"
#include "mcu_probe.h"
#include "netlog.h"
#include "ota.h"
#include "ota_pubkey.h"
#include "ota_test.h"
#include "wdog.h"
#include "wifi_sta.h"
#ifdef BLE_PROBE
#include "ble_probe.h"
#endif

#if __has_include("wifi_credentials.h")
#include "wifi_credentials.h"
#else
#error "Missing apps/example-switch/wifi_credentials.h: copy wifi_credentials.h.example and fill in WIFI_SSID and WIFI_PASSWORD"
#endif

static const uint8_t ota_key[32] = OTA_PUBLIC_KEY_INIT;
static const wifi_sta_config wifi = { .ssid = WIFI_SSID, .password = WIFI_PASSWORD, .onIP = hap_app_notify_network_up };

int main(void)
{
    netlog_init();                           // tee the console into the network log
    ota_boot_check();                        // may roll back to the previous image
    wdog_start();                            // faults and CPU hogs reset, so trial boots get counted
    wlan_network();                          // LwIP + radio on (SDK)
    netlog_start(NETLOG_PORT);
    ota_start(&(const ota_options) { .port = OTA_PORT, .publicKey = ota_key });
    hap_app_start(accessory_config(ota_test_confirm_hook)); // a running HAP server confirms an OTA trial
    mcu_probe_start();                       // TuyaMCU link, read-only, logged
    ota_test_start();                        // no-op unless built with OTA_TEST
    wifi_sta_start(&wifi);
#ifdef BLE_PROBE
    ble_probe_start(NULL);                    // measurement build only (make BT=1)
#endif
    vTaskStartScheduler();
    return 0;
}
