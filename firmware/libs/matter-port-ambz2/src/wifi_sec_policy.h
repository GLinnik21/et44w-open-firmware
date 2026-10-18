/* Which security to join a network with, pure: netctl.c maps the answer to an rtw_security_t.
 *
 * The credentials decide whether the network is open: with a passphrase the station never joins an open AP, so an
 * open AP that copies the SSID (stronger signal or not) cannot downgrade the link; without one it never tries a
 * secured AP. Among the APs of the last scan that carry the SSID and fit the credentials, the strongest (the scan
 * keeps them sorted by RSSI) picks between WPA3, WPA2/WPA3 mixed and plain WPA2. No scan entry: WPA2 with a
 * passphrase, open without (wifi-sta's AUTO). */
#ifndef MTP_WIFI_SEC_POLICY_H
#define MTP_WIFI_SEC_POLICY_H

#include <stdbool.h>
#include <string.h>

#include "mt_netctl.h"

typedef enum {
    MTP_SEC_AUTO = 0,   /* WPA2-AES-PSK with a passphrase, open without */
    MTP_SEC_WPA3,       /* WPA3-SAE only */
    MTP_SEC_WPA2_WPA3,  /* transition mode */
} mtp_sec;

static inline mtp_sec mtp_sec_pick(const mt_netctl_ap *aps, unsigned n, const uint8_t *ssid, size_t ssid_len,
                                   bool has_cred)
{
    for (unsigned i = 0; i < n; i++) {
        uint8_t s = aps[i].security;
        if (aps[i].ssid_len != ssid_len || memcmp(aps[i].ssid, ssid, ssid_len)) continue;
        if (!has_cred) return MTP_SEC_AUTO;                     /* open */
        if (!(s & (MT_WIFI_SEC_WPA | MT_WIFI_SEC_WPA2 | MT_WIFI_SEC_WPA3))) continue; /* open or WEP: skipped */
        if ((s & MT_WIFI_SEC_WPA3) && (s & MT_WIFI_SEC_WPA2)) return MTP_SEC_WPA2_WPA3;
        if (s & MT_WIFI_SEC_WPA3) return MTP_SEC_WPA3;
        return MTP_SEC_AUTO;
    }
    return MTP_SEC_AUTO;
}

#endif
