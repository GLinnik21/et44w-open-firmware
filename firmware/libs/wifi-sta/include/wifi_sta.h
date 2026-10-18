// Wi-Fi station: connects with the current credentials, runs DHCP, and keeps the link up. Knows
// nothing about Matter; the caller passes callbacks.
#ifndef WIFI_STA_H
#define WIFI_STA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char* ssid;
    const char* password; // WPA2-PSK; never logged
    void (*onIP)(void);   // from the Wi-Fi task, each time an IPv4 address has been obtained
} wifi_sta_config;

/** Starts the Wi-Fi task. Needs wlan_network() (LwIP + wifi_on) started first; config must stay valid.
 *  config->ssid == NULL: stay down until credentials arrive (wifi_sta_set_credentials); a non-NULL ssid is copied as
 *  the initial network. */
void wifi_sta_start(const wifi_sta_config* config);

#define WIFI_STA_SSID_MAX 32
#define WIFI_STA_PASS_MAX 64
#define WIFI_STA_SEC_AUTO (-1) // WPA2-AES-PSK with a password, open without

typedef enum {
    WIFI_STA_DOWN_CONNECT_FAILED, // association / authentication failed
    WIFI_STA_DOWN_NO_DHCP,        // associated, no lease within the timeout
    WIFI_STA_DOWN_LINK_LOST,      // was up, link or lease lost
} wifi_sta_down;

/** Switches to this network (copied; ssid_len 0 = disconnect and stay down). Takes effect at once: an
 *  established link is dropped. security: an rtw_security_t value wifi_connect accepts or WIFI_STA_SEC_AUTO (other
 *  values are logged and treated as AUTO). Any task. Returns the
 *  generation of these credentials (never 0), 0 if a length is out of range. */
uint32_t wifi_sta_set_credentials(const uint8_t* ssid, size_t ssid_len, const uint8_t* pass, size_t pass_len,
                                  int32_t security);
/** Generation of the credentials the Wi-Fi task is using (valid inside onIP); 0 before the first. */
uint32_t wifi_sta_generation(void);
/** Called from the Wi-Fi task each time a connect attempt fails or an established link goes down, with the
 *  generation of the credentials it was using. NULL = none. */
void wifi_sta_set_on_down(void (*on_down)(wifi_sta_down why, uint32_t gen));

#endif
