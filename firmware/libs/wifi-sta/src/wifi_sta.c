#include "wifi_sta.h"
#include "ipv6_setup.h"

#include "FreeRTOS.h"
#include "task.h"
#include "lwip_netconf.h"
#include "wifi_conf.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIFI_TASK_STACK_WORDS 640 // measured use ~360 words
#define WIFI_TASK_PRIORITY    (tskIDLE_PRIORITY + 3)
#define WIFI_POLL_MS          2000
#define DHCP_TIMEOUT_MS       15000

static const wifi_sta_config* cfg;

#if WIFI_STA_RUNTIME
// Credentials set at runtime (wifi_sta.h). `want` is written by any task under a critical section; the Wi-Fi task
// works on its snapshot `cur` and notices a change through the generation counter.
typedef struct {
    char ssid[WIFI_STA_SSID_MAX + 1];
    char pass[WIFI_STA_PASS_MAX + 1];
    int32_t security;
    uint32_t gen;
} sta_creds;
static sta_creds want, cur;
static void (*volatile on_down)(wifi_sta_down why, uint32_t gen);

static bool creds_changed(void) {
    return *(volatile uint32_t*) &want.gen != cur.gen;
}

static void creds_take(void) {
    taskENTER_CRITICAL();
    cur = want;
    taskEXIT_CRITICAL();
}

static void report_down(wifi_sta_down why) {
    void (*f)(wifi_sta_down, uint32_t) = on_down;
    if (f) {
        f(why, cur.gen);
    }
}

// Waits up to ms, returning early when new credentials arrive.
static void wait_or_change(int ms) {
    for (int waited = 0; waited < ms && !creds_changed(); waited += 200) {
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

// The rtw_security_t values wifi_connect accepts (not UNKNOWN, not the 32-bit filler).
static bool joinable(int32_t s) {
    switch (s) {
        case RTW_SECURITY_OPEN: case RTW_SECURITY_WEP_PSK: case RTW_SECURITY_WEP_SHARED:
        case RTW_SECURITY_WPA_TKIP_PSK: case RTW_SECURITY_WPA_AES_PSK: case RTW_SECURITY_WPA_MIXED_PSK:
        case RTW_SECURITY_WPA2_TKIP_PSK: case RTW_SECURITY_WPA2_AES_PSK: case RTW_SECURITY_WPA2_MIXED_PSK:
        case RTW_SECURITY_WPA2_AES_CMAC: case RTW_SECURITY_WPA_WPA2_TKIP_PSK: case RTW_SECURITY_WPA_WPA2_AES_PSK:
        case RTW_SECURITY_WPA_WPA2_MIXED_PSK: case RTW_SECURITY_WPA3_AES_PSK: case RTW_SECURITY_WPA2_WPA3_MIXED:
            return true;
        default:
            return false;
    }
}

static rtw_security_t security_of(const sta_creds* c) {
    if (c->security != WIFI_STA_SEC_AUTO) {
        return (rtw_security_t) c->security; // checked by wifi_sta_set_credentials
    }
    return c->pass[0] ? RTW_SECURITY_WPA2_AES_PSK : RTW_SECURITY_OPEN;
}

uint32_t wifi_sta_set_credentials(const uint8_t* ssid, size_t ssid_len, const uint8_t* pass, size_t pass_len,
                                  int32_t security) {
    uint32_t gen;
    if (ssid_len > WIFI_STA_SSID_MAX || pass_len > WIFI_STA_PASS_MAX) {
        return 0;
    }
    if (security != WIFI_STA_SEC_AUTO && !joinable(security)) {
        printf("wifi: security %ld not supported, guessing from the password\n", (long) security);
        security = WIFI_STA_SEC_AUTO;
    }
    taskENTER_CRITICAL();
    memset(want.ssid, 0, sizeof want.ssid);
    memset(want.pass, 0, sizeof want.pass);
    if (ssid_len) {
        memcpy(want.ssid, ssid, ssid_len);
    }
    if (pass_len) {
        memcpy(want.pass, pass, pass_len);
    }
    want.security = security;
    if (++want.gen == 0) {
        want.gen = 1;
    }
    gen = want.gen;
    taskEXIT_CRITICAL();
    return gen;
}

uint32_t wifi_sta_generation(void) {
    return cur.gen;
}

void wifi_sta_set_on_down(void (*f)(wifi_sta_down why, uint32_t gen)) {
    on_down = f;
}

#define STA_SSID         cur.ssid
#define STA_PASS         cur.pass
#define STA_SECURITY     security_of(&cur)
#define STA_DOWN(why)    report_down(why)
#define STA_CHANGED()    creds_changed()
#define STA_RETRY_WAIT() wait_or_change(5000)
#else
#define STA_SSID         cfg->ssid
#define STA_PASS         cfg->password
#define STA_SECURITY     RTW_SECURITY_WPA2_AES_PSK
#define STA_DOWN(why)
#define STA_CHANGED()    0
#define STA_RETRY_WAIT() vTaskDelay(pdMS_TO_TICKS(5000))
#endif

static bool has_ip(void) {
    return *(const uint32_t*) LwIP_GetIP(&xnetif[0]) != 0;
}

// Waits for wlan_network()'s init task to switch the radio on.
static void wait_for_radio(void) {
    while (!wifi_is_up(RTW_STA_INTERFACE)) {
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

static bool connect_and_dhcp(void) {
    // The password is never logged.
    printf("wifi: connecting to \"%s\"\r\n", STA_SSID);
    if (wifi_connect((char*) STA_SSID, STA_SECURITY, (char*) STA_PASS, strlen(STA_SSID),
                     strlen(STA_PASS), -1, NULL) != RTW_SUCCESS) {
        printf("wifi: connect failed\r\n");
        STA_DOWN(WIFI_STA_DOWN_CONNECT_FAILED);
        return false;
    }
    LwIP_DHCP(0, DHCP_START);
    for (int waited = 0; waited < DHCP_TIMEOUT_MS; waited += 200) {
        if (has_ip()) {
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    printf("wifi: no DHCP lease\r\n");
    STA_DOWN(WIFI_STA_DOWN_NO_DHCP);
    return false;
}

static void wifi_task(void* arg) {
    (void) arg;
    wait_for_radio();
    ipv6_setup();
    for (;;) {
#if WIFI_STA_RUNTIME
        creds_take();
        if (!cur.ssid[0]) { // no network: stay down until one is set
            if (wifi_is_connected_to_ap() == RTW_SUCCESS) {
                wifi_disconnect();
            }
            while (!creds_changed()) {
                vTaskDelay(pdMS_TO_TICKS(200));
            }
            continue;
        }
        if (wifi_is_connected_to_ap() == RTW_SUCCESS) {
            wifi_disconnect(); // leaving the previous network
        }
#endif
        if (!connect_and_dhcp()) {
            STA_RETRY_WAIT();
            continue;
        }
        printf("wifi: got IP\r\n");
        cfg->onIP();
        // The SDK's autoreconnect (set in wlan_network) handles drops; we only notice a lost link
        // or lease and redo the whole sequence.
        while (wifi_is_connected_to_ap() == RTW_SUCCESS && has_ip() && !STA_CHANGED()) {
            vTaskDelay(pdMS_TO_TICKS(WIFI_POLL_MS));
        }
#if WIFI_STA_RUNTIME
        if (creds_changed()) {
            printf("wifi: switching network\r\n");
            continue;
        }
#endif
        printf("wifi: link lost\r\n");
        STA_DOWN(WIFI_STA_DOWN_LINK_LOST);
    }
}

void wifi_sta_start(const wifi_sta_config* config) {
    cfg = config;
#if WIFI_STA_RUNTIME
    if (config->ssid) {
        wifi_sta_set_credentials((const uint8_t*) config->ssid, strlen(config->ssid),
                                 (const uint8_t*) config->password, strlen(config->password), WIFI_STA_SEC_AUTO);
    }
#endif
    if (xTaskCreate(wifi_task, "wifi", WIFI_TASK_STACK_WORDS, NULL, WIFI_TASK_PRIORITY, NULL) != pdPASS) {
        printf("wifi: task create failed\r\n");
    }
}
