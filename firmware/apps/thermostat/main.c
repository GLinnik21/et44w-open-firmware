// Boot wiring only: console, network log, OTA, watchdog, Wi-Fi, HAP task, MCU link, web page, scheduler.
#include "FreeRTOS.h"
#include "task.h"
#include "main.h"

#include <stdio.h>

#include "accessory.h"
#include "config.h"
#include "clock.h"
#include "mcu_link.h"
#include "netlog.h"
#include "ota.h"
#include "ota_pubkey.h"
#include "ota_test.h"
#include "wdog.h"
#include "web.h"
#include "wifi_sta.h"

#if __has_include("wifi_credentials.h")
#include "wifi_credentials.h"
#else
#error "Missing wifi_credentials.h: copy wifi_credentials.h.example and fill in WIFI_SSID and WIFI_PASSWORD"
#endif

static void OnIP(void)
{
    clock_start();
    hap_app_notify_network_up();
}

static const uint8_t ota_key[32] = OTA_PUBLIC_KEY_INIT;
static const wifi_sta_config wifi = { .ssid = WIFI_SSID, .password = WIFI_PASSWORD, .onIP = OnIP };

int main(void)
{
    netlog_init();                           // tee the console into the network log
    ota_boot_check();                        // may roll back to the previous image
    wdog_start();                            // faults and CPU hogs reset, so trial boots get counted
    wlan_network();                          // LwIP + radio on (SDK)
    netlog_start(NETLOG_PORT);
    ota_start(&(const ota_options) { .port = OTA_PORT, .publicKey = ota_key });
    hap_app_start(accessory_config(ota_test_confirm_hook)); // a running HAP server confirms an OTA trial
    ota_test_start();                        // no-op unless built with OTA_TEST
    if (!mcu_link_start()) {
        printf("[thermostat] MCU link failed: HomeKit sees no thermostat data\n");
    }
    web_start(THERMOSTAT_NAME, THERMOSTAT_FIRMWARE);
    wifi_sta_start(&wifi);
    vTaskStartScheduler();
    return 0;
}
