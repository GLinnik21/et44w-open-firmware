/* Host tests of wifi_sec_policy.h: the security a stored network is joined with. */
#include <stdio.h>

#include "wifi_sec_policy.h"

static int *F;
#define CHECK(c) do { if (!(c)) { (*F)++; fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); } } while (0)

static mt_netctl_ap ap(const char *ssid, uint8_t sec, int8_t rssi)
{
    mt_netctl_ap a = { .security = sec, .rssi = rssi };
    a.ssid_len = (uint8_t)strlen(ssid);
    memcpy(a.ssid, ssid, a.ssid_len);
    return a;
}

#define PICK(aps, n, ssid, cred) mtp_sec_pick(aps, n, (const uint8_t *)(ssid), strlen(ssid), cred)

void test_wifi_sec(int *fails)
{
    F = fails;
    /* strongest first, as netctl's scan keeps them */
    mt_netctl_ap rogue[] = { ap("Home", MT_WIFI_SEC_UNENCRYPTED, -30), ap("Home", MT_WIFI_SEC_WPA2, -60) };
    mt_netctl_ap wpa3[] = { ap("Other", MT_WIFI_SEC_WPA2, -20), ap("Home", MT_WIFI_SEC_WPA3, -50) };
    mt_netctl_ap mixed[] = { ap("Home", MT_WIFI_SEC_UNENCRYPTED, -20),
                             ap("Home", MT_WIFI_SEC_WPA2 | MT_WIFI_SEC_WPA3, -40) };
    mt_netctl_ap only_open[] = { ap("Home", MT_WIFI_SEC_UNENCRYPTED, -30), ap("Home", MT_WIFI_SEC_WEP, -40) };

    /* a stronger open AP with the stored SSID never makes a passphrase network open */
    CHECK(PICK(rogue, 2, "Home", true) == MTP_SEC_AUTO);
    CHECK(PICK(only_open, 2, "Home", true) == MTP_SEC_AUTO);       /* WPA2 attempt, not open */
    CHECK(PICK(mixed, 2, "Home", true) == MTP_SEC_WPA2_WPA3);
    CHECK(PICK(wpa3, 2, "Home", true) == MTP_SEC_WPA3);
    CHECK(PICK(wpa3, 2, "Nope", true) == MTP_SEC_AUTO);            /* not in the scan */
    CHECK(PICK(wpa3, 0, "Home", true) == MTP_SEC_AUTO);            /* no scan */
    /* without credentials: open (AUTO), whatever the scan says */
    CHECK(PICK(wpa3, 2, "Home", false) == MTP_SEC_AUTO);
    CHECK(PICK(rogue, 2, "Home", false) == MTP_SEC_AUTO);
    /* SSIDs compare by length too */
    CHECK(PICK(wpa3, 2, "Hom", true) == MTP_SEC_AUTO);
}
