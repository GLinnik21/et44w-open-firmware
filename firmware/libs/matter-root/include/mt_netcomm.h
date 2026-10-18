/* Network Commissioning cluster (0x31, spec 1.3 section 11.9, revision 2, Wi-Fi feature only), endpoint 0.
 *
 *  - Attributes: MaxNetworks (1), Networks (<= 1 NetworkInfoStruct {NetworkID, Connected}), ScanMaxTimeSeconds,
 *    ConnectMaxTimeSeconds, InterfaceEnabled (writable), LastNetworkingStatus, LastNetworkID,
 *    LastConnectErrorValue (nullable), SupportedWiFiBands.
 *  - Commands: ScanNetworks, AddOrUpdateWiFiNetwork, RemoveNetwork, ConnectNetwork, ReorderNetwork; responses
 *    ScanNetworksResponse, NetworkConfigResponse, ConnectNetworkResponse. Thread/Ethernet/PDC are not offered.
 *  - Staging: AddOrUpdate and Remove need an armed fail-safe (of the accessing fabric) and only change RAM; the
 *    persisted network (mt_netctl_ops.save/erase) changes at CommissioningComplete through the mt_root stage
 *    hook, and fail-safe expiry drops the staged change and, if the station was moved, calls netctl.revert.
 *  - ConnectNetwork and ScanNetworks answer later when the port needs time: the handler returns MT_IM_DEFER and
 *    mt_netcomm_connect_done / mt_netcomm_scan_done send the response through mt_im_invoke_done (matter-im keeps
 *    the exchange open). One such operation at a time; other commands meanwhile get BUSY (as chip does).
 *    ConnectNetwork to the network the station is already on (same SSID and credentials) answers Success at once.
 *  - The module has exactly one network slot. A different SSID while the slot is taken is BoundsExceeded, as in
 *    the spec, unless cfg.replace_when_full (recommissioning then overwrites the old network).
 * Command rules follow connectedhomeip v1.3-branch network-commissioning.cpp; cluster rev, features, ids come
 * from the 1.3 data model (NetworkCommissioningCluster.xml). Pure C11, no allocation. */
#ifndef MT_NETCOMM_H
#define MT_NETCOMM_H

#include "mt_netctl.h"
#include "mt_root_comm.h"

#define MT_NETCOMM_CLUSTER_ID 0x0031u
#define MT_NETCOMM_SCRATCH 640        /* minimum mt_netcomm_cfg.scratch: the encoded scan results */
#define MT_NETCOMM_MAX_SCAN_RESULTS 10 /* strongest first (chip's kMaxNetworksInScanResponse) */

/* NetworkCommissioningStatusEnum (spec 11.9.5.1). */
enum { MT_NET_OK = 0, MT_NET_OUT_OF_RANGE = 1, MT_NET_BOUNDS_EXCEEDED = 2, MT_NET_ID_NOT_FOUND = 3,
       MT_NET_DUPLICATE_ID = 4, MT_NET_NETWORK_NOT_FOUND = 5, MT_NET_REGULATORY_ERROR = 6, MT_NET_AUTH_FAILURE = 7,
       MT_NET_UNSUPPORTED_SECURITY = 8, MT_NET_OTHER_CONNECTION_FAILURE = 9, MT_NET_IPV6_FAILED = 10,
       MT_NET_IP_BIND_FAILED = 11, MT_NET_UNKNOWN_ERROR = 12 };

typedef struct {
    const mt_netctl_ops *net;
    void *ctx;                     /* passed to every netctl op */
    mt_root *root;                 /* fail-safe, clock, breadcrumb; the stage hook is registered on it */
    uint8_t bands;                 /* SupportedWiFiBands: bit (1 << MT_WIFI_BAND_*), at least one */
    uint8_t scan_max_s;            /* ScanMaxTimeSeconds; ScanNetworks fails after this long (0 = 10) */
    uint8_t connect_max_s;         /* ConnectMaxTimeSeconds (0 = 30) */
    bool replace_when_full;
    mt_buf scratch;                /* >= MT_NETCOMM_SCRATCH, used during scan completion only */
} mt_netcomm_cfg;

typedef struct mt_netcomm {
    mt_netcomm_cfg c;
    mt_dm_cluster cluster;         /* list in endpoint 0 */
    struct {
        uint8_t kind;              /* none / set / remove */
        uint8_t ssid_len, cred_len;
        uint8_t ssid[MT_NETCTL_SSID_MAX];
        uint8_t cred[MT_NETCTL_CRED_MAX];
    } stage;
    struct {                       /* the one operation in flight */
        uint8_t kind;              /* none / scan / connect */
        bool aborted;              /* fail-safe expired: answered as a failure by the next poll */
        uint16_t session, exch;
        uint32_t deadline;
        bool crumb_set;
        uint64_t crumb;
        uint8_t id_len;            /* connect: network being joined */
        uint8_t id[MT_NETCTL_SSID_MAX];
    } op;
    bool switched;                 /* ConnectNetwork moved the station: revert on fail-safe expiry */
    bool persisted;                /* the stage is saved, CommissioningComplete not finished (undo restores) */
    bool enabled;                  /* InterfaceEnabled */
    bool have_status, have_error;
    uint8_t last_status;
    int32_t last_error;
    uint8_t last_id_len;           /* 0 = LastNetworkID null */
    uint8_t last_id[MT_NETCTL_SSID_MAX];
} mt_netcomm;

/* MT_ERR_INVALID for a missing op, root or too small a scratch. Registers the stage hook on cfg->root; the object
 * must not move afterwards. Not cleared by a fail-safe: the Last* attributes survive. */
mt_err mt_netcomm_init(mt_netcomm *n, const mt_netcomm_cfg *cfg);

/* The port finished the join started by netctl.connect. status: MT_NET_*; err: the platform's error value for
 * ConnectNetworkResponse.ErrorValue (NULL = null). No-op when no connect is pending (late result, expired fail-safe). */
void mt_netcomm_connect_done(mt_netcomm *n, uint8_t status, const int32_t *err);
/* The port finished the scan: status MT_NET_OK with the list readable through netctl.scan_result, or an error. */
void mt_netcomm_scan_done(mt_netcomm *n, uint8_t status);
/* Expires a pending scan/connect that ran out of time. Returns ms until the next deadline, UINT32_MAX when idle. */
uint32_t mt_netcomm_poll(mt_netcomm *n);

#endif
