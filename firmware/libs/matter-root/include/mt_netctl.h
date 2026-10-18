/* netctl: the port interface behind Network Commissioning (Wi-Fi). The platform (matter-port-*) implements it over
 * its Wi-Fi station driver and the persisted WIFI record; mt_netcomm only stages changes and
 * calls these. Everything is non-blocking: connect and scan start work and report back through
 * mt_netcomm_connect_done / mt_netcomm_scan_done (from the Matter task, never inside the op that started them).
 * Pure C11 header, no allocation. */
#ifndef MT_NETCTL_H
#define MT_NETCTL_H

#include "mt_core.h"

#define MT_NETCTL_SSID_MAX 32
#define MT_NETCTL_CRED_MAX 64   /* passphrase 8..63 or 64 hex digits (spec 11.9.7.3) */

/* WiFiBandEnum (spec 11.9.5.2); SupportedWiFiBands is a bitmask of 1 << band in mt_netcomm_cfg. */
enum { MT_WIFI_BAND_2G4 = 0, MT_WIFI_BAND_3G65 = 1, MT_WIFI_BAND_5G = 2, MT_WIFI_BAND_6G = 3, MT_WIFI_BAND_60G = 4,
       MT_WIFI_BAND_1G = 5 };
/* WiFiSecurityBitmap (spec 11.9.5.4). */
enum { MT_WIFI_SEC_UNENCRYPTED = 1, MT_WIFI_SEC_WEP = 2, MT_WIFI_SEC_WPA = 4, MT_WIFI_SEC_WPA2 = 8,
       MT_WIFI_SEC_WPA3 = 16 };

/* One access point of a scan (WiFiInterfaceScanResultStruct). */
typedef struct {
    uint8_t security;                 /* MT_WIFI_SEC_* bits */
    uint8_t ssid[MT_NETCTL_SSID_MAX];
    uint8_t ssid_len;
    uint8_t bssid[6];
    uint16_t channel;
    uint8_t band;                     /* MT_WIFI_BAND_* */
    int8_t rssi;                      /* dBm */
} mt_netctl_ap;

typedef struct {
    /* The persisted network (the one the module joins at boot). false if none. ssid has room for 32 bytes. */
    bool (*saved)(void *ctx, uint8_t ssid[MT_NETCTL_SSID_MAX], size_t *len);
    /* Persist ssid/credentials as the one network (replacing any); called at CommissioningComplete. */
    mt_err (*save)(void *ctx, mt_span ssid, mt_span creds);
    /* Forget the persisted network (a RemoveNetwork that was committed). */
    mt_err (*erase)(void *ctx);
    /* The SSID the station is associated with right now (an IP link is not required). false if none. */
    bool (*connected)(void *ctx, uint8_t ssid[MT_NETCTL_SSID_MAX], size_t *len);
    /* Is the station associated with `ssid` using exactly these credentials? Decides whether ConnectNetwork can
     * answer at once or must rejoin. May be NULL: an SSID match then counts. */
    bool (*is_current)(void *ctx, mt_span ssid, mt_span creds);
    /* Start joining `ssid` with `creds` (NULL = the persisted credentials); the old link may drop. The result goes
     * to mt_netcomm_connect_done. A non-MT_OK return means nothing was started. */
    mt_err (*connect)(void *ctx, mt_span ssid, const mt_span *creds);
    /* The fail-safe expired after the node switched network: go back to the persisted one (or stay down if none). */
    void (*revert)(void *ctx);
    /* Start a scan, all networks (ssid.len == 0) or one SSID; the result goes to mt_netcomm_scan_done. */
    mt_err (*scan)(void *ctx, mt_span ssid);
    /* Result `idx` of the last finished scan; false past the end. */
    bool (*scan_result)(void *ctx, uint16_t idx, mt_netctl_ap *out);
    /* InterfaceEnabled written by a controller. May be NULL (the attribute is then only remembered in RAM). */
    mt_err (*set_enabled)(void *ctx, bool enabled);
    /* Undo the last save / erase: persist again the network that was stored before it (or none). Called when a
     * later step of the same CommissioningComplete failed. May be NULL (the new record then stays). */
    mt_err (*restore)(void *ctx);
} mt_netctl_ops;

#endif
