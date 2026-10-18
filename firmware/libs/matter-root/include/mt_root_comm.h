/* Matter endpoint-0 commissioning clusters and the commissioning context they share. Pure C11, no allocation.
 *
 * Clusters (one source file each, all served from one mt_root object):
 *  - General Commissioning 0x30 (spec 1.3 section 11.10, revision 1): Breadcrumb, BasicCommissioningInfo,
 *    RegulatoryConfig, LocationCapability, SupportsConcurrentConnection; ArmFailSafe, SetRegulatoryConfig,
 *    CommissioningComplete. The fail-safe timer lives here (mt_failsafe).
 *  - Operational Credentials 0x3E (11.18, revision 1): NOCs, Fabrics, SupportedFabrics, CommissionedFabrics,
 *    TrustedRootCertificates, CurrentFabricIndex; AttestationRequest, CertificateChainRequest, CSRRequest,
 *    AddNOC, UpdateNOC, UpdateFabricLabel, RemoveFabric, AddTrustedRootCertificate.
 *  - Access Control 0x1F (9.10, revision 1): ACL (fabric-scoped list, read/write/append), the three limit
 *    attributes, and the access check of section 6.6.6 (mt_acl_check / mt_root_access). No Extension attribute,
 *    no AccessControlEntryChanged event (Apple Home does not subscribe to it, docs/matter-apple-trace.md).
 *  - Time Synchronization 0x38 (11.17, revision 2, no features): UTCTime, Granularity, TimeSource and SetUTCTime
 *    (Administer). Kept as an offset to the node clock; mt_root_utc_now() feeds certificate validity checks.
 *  - Group Key Management 0x3F (11.2, revision 2 as chip v1.3 encodes it): only the IPK key set (id 0, part of
 *    the fabric). GroupKeyMap/GroupTable are empty; groups are not supported.
 * Status codes and command rules follow the spec sections above, cross-checked against connectedhomeip
 * v1.3-branch (general-commissioning-server.cpp, operational-credentials-server.cpp,
 * access-control-server.cpp, group-key-mgmt-server.cpp, access/AccessControl.cpp).
 *
 * Ownership: matter-node owns the mt_root, the fabric table, the RNG and the sessions; it implements
 * mt_root_ops, lists the four clusters in endpoint 0, calls mt_root_bind_dm() after mt_dm_init(), passes
 * mt_root_access as the mt_dm access callback and calls mt_root_poll() from its poll loop. */
#ifndef MT_ROOT_COMM_H
#define MT_ROOT_COMM_H

#include "mt_cert.h"
#include "mt_crypto.h"
#include "mt_dm.h"
#include "mt_fabric.h"
#include "mt_root.h"

#define MT_GENCOMM_CLUSTER_ID 0x0030u
#define MT_OPCREDS_CLUSTER_ID 0x003Eu
#define MT_ACL_CLUSTER_ID 0x001Fu
#define MT_GKM_CLUSTER_ID 0x003Fu
#define MT_TIMESYNC_CLUSTER_ID 0x0038u

#define MT_ROOT_FAILSAFE_EXPIRY_S 60          /* BasicCommissioningInfo.FailSafeExpiryLengthSeconds */
#define MT_ROOT_FAILSAFE_MAX_CUMULATIVE_S 900 /* BasicCommissioningInfo.MaxCumulativeFailsafeSeconds */
#define MT_ROOT_SCRATCH MT_FABRIC_SCRATCH     /* minimum mt_root_cfg.scratch: chain verify, cert reads, TBS of
                                               * attestation/NOCSR elements || challenge */
#define MT_ROOT_CHALLENGE_LEN 16              /* AttestationChallenge (spec 4.13.2.6 PASE, 4.14.2.6 CASE) */
#define MT_ROOT_NONCE_LEN 32                  /* AttestationNonce / CSRNonce */
#define MT_ROOT_MAX_GROUPS_PER_FABRIC 0       /* no Groups cluster */
#define MT_ROOT_MAX_GROUP_KEYS_PER_FABRIC 1   /* the IPK key set */

/* RegulatoryLocationTypeEnum (11.10.5.1). */
enum { MT_REG_INDOOR = 0, MT_REG_OUTDOOR = 1, MT_REG_INDOOR_OUTDOOR = 2 };
/* CommissioningErrorEnum (11.10.5.2). */
enum { MT_COMM_OK = 0, MT_COMM_VALUE_OUTSIDE_RANGE = 1, MT_COMM_INVALID_AUTH = 2, MT_COMM_NO_FAILSAFE = 3,
       MT_COMM_BUSY_WITH_OTHER_ADMIN = 4 };
/* NodeOperationalCertStatusEnum (11.18.4.6). */
enum { MT_NOC_OK = 0, MT_NOC_INVALID_PUBLIC_KEY = 1, MT_NOC_INVALID_NODE_OP_ID = 2, MT_NOC_INVALID_NOC = 3,
       MT_NOC_MISSING_CSR = 4, MT_NOC_TABLE_FULL = 5, MT_NOC_INVALID_ADMIN_SUBJECT = 6, MT_NOC_FABRIC_CONFLICT = 9,
       MT_NOC_LABEL_CONFLICT = 10, MT_NOC_INVALID_FABRIC_INDEX = 11 };

/* Time Synchronization (11.17). Times are "epoch-us": microseconds since the Matter epoch, 2000-01-01 00:00:00 UTC
 * (unix time minus 946684800 s). GranularityEnum (11.17.5.1) and TimeSourceEnum (11.17.5.2, the ones we name). */
enum { MT_TIME_GRAN_NONE = 0, MT_TIME_GRAN_MINUTES = 1, MT_TIME_GRAN_SECONDS = 2, MT_TIME_GRAN_MS = 3,
       MT_TIME_GRAN_US = 4 };
enum { MT_TIME_SRC_NONE = 0, MT_TIME_SRC_UNKNOWN = 1, MT_TIME_SRC_ADMIN = 2, MT_TIME_SRC_NODE_TIME = 3,
       MT_TIME_SRC_NONMATTER_SNTP = 4, MT_TIME_SRC_NONMATTER_NTP = 5, MT_TIME_SRC_MATTER_SNTP = 6,
       MT_TIME_SRC_MAX = 0x10 };
#define MT_TIME_CST_NOT_ACCEPTED 2u   /* StatusCodeEnum.TimeNotAccepted (cluster status of SetUTCTime) */

/* ---- fail-safe context (11.10.7.2) ---- */

enum { /* mt_failsafe.flags */
    MT_FS_ADD_TRC = 1u << 0,     /* AddTrustedRootCertificate ran: a root is staged in the fabric table */
    MT_FS_ADD_NOC = 1u << 1,     /* AddNOC ran: a pending new fabric exists (index = mt_failsafe.fabric) */
    MT_FS_UPDATE_NOC = 1u << 2,  /* UpdateNOC ran: a pending credential update of mt_failsafe.fabric */
    MT_FS_CSR = 1u << 3,         /* CSRRequest staged a new operational key pair in the fabric table */
    MT_FS_CSR_UPDATE = 1u << 4,  /* ... and that CSR had IsForUpdateNOC = true */
    MT_FS_NETWORK = 1u << 5      /* Network Commissioning staged or switched a Wi-Fi network (mt_netcomm) */
};

typedef struct {
    bool armed;
    uint8_t fabric;      /* accessing fabric that armed it (0 = PASE before AddNOC); AddNOC moves it to the new one */
    uint8_t flags;       /* MT_FS_* */
    uint16_t session;    /* session that armed it last (informational) */
    uint32_t deadline;   /* now_ms() value at which it expires */
    uint32_t limit;      /* first arm + MaxCumulativeFailsafeSeconds: no re-arm extends past this */
} mt_failsafe;

/* ---- what the node supplies ---- */

/* The invoking or reading secure session. */
typedef struct {
    uint8_t auth;                       /* MT_IM_AUTH_PASE / MT_IM_AUTH_CASE */
    uint8_t fabric;                     /* accessing fabric index, 0 = none */
    uint64_t peer_node;                 /* CASE: peer operational node ID; PASE: 0 */
    uint32_t cats[MT_CERT_MAX_CATS];    /* CASE: the peer NOC's CASE Authenticated Tags */
    uint8_t n_cats;
    uint8_t challenge[MT_ROOT_CHALLENGE_LEN]; /* AttestationChallenge of the session's keys */
} mt_root_session;

/* Device attestation credentials (spec 6.2): DER DAC and PAI, CMS certification declaration, and an ECDSA-SHA256
 * signer with the DAC private key (the key itself stays in the port). Spans must outlive the mt_root. */
typedef struct {
    mt_span dac, pai, cd;
    uint16_t vendor_id, product_id;     /* the DAC's VID/PID, for the node's advertising; the clusters don't use them */
    void *ctx;
    mt_err (*sign)(void *ctx, mt_span msg, uint8_t sig[MT_P256_SIG_LEN]);
} mt_root_creds;

typedef enum {
    /* The fail-safe ended without CommissioningComplete (timer, ArmFailSafe(0) or a removed fabric). The fabric
     * table is already rolled back. Node: drop staged Wi-Fi and return to the previous network; if fs_flags has
     * MT_FS_ADD_NOC or MT_FS_UPDATE_NOC close the CASE sessions of `fabric`; with MT_FS_ADD_NOC also unbind the
     * PASE session from it and withdraw its operational mDNS record. */
    MT_ROOT_EV_FAILSAFE_EXPIRED,
    /* AddNOC staged fabric `fabric`: advertise its operational record so CASE can reach it. */
    MT_ROOT_EV_FABRIC_ADDED,
    /* UpdateNOC staged new credentials for `fabric`: after the response, close the fabric's other sessions
     * (all but `session`) and refresh mDNS. */
    MT_ROOT_EV_NOC_UPDATED,
    /* RemoveFabric removed `fabric` (already erased). After the response is sent (never inside the invoke, or
     * it is lost) close its sessions, including `session` if it belongs to it; mt_im_on_fabric_removed; drop
     * the mDNS record; reopen commissioning if no fabric is left. */
    MT_ROOT_EV_FABRIC_REMOVED,
    /* CommissioningComplete succeeded for `fabric` (committed, fail-safe disarmed): close the commissioning
     * window / BLE. */
    MT_ROOT_EV_COMMISSIONED
} mt_root_event;

typedef struct {
    uint32_t (*now_ms)(void *ctx);
    /* Describe secure session `session`; false if it is gone. */
    bool (*session)(void *ctx, uint16_t session, mt_root_session *out);
    /* AddNOC on a PASE session: from now on the session's accessing fabric is `fabric` (spec 11.18.6.8). */
    void (*adopt_fabric)(void *ctx, uint16_t session, uint8_t fabric);
    /* Is a commissioning window open? (a CASE session may not arm a disarmed fail-safe while it is) */
    bool (*window_open)(void *ctx);
    /* CommissioningComplete, first, before any flash write (the stage hook's Wi-Fi, then the fabric table follow;
     * the node tears BLE down here). Non-MT_OK answers FAILURE and leaves the fail-safe armed
     * with nothing persisted. May be NULL. */
    mt_err (*commit)(void *ctx, uint8_t fabric);
    /* Notifications, see mt_root_event. May be NULL. */
    void (*event)(void *ctx, mt_root_event ev, uint8_t fabric, uint16_t session, uint8_t fs_flags);
    /* Operational key pair for CSRRequest. NULL = mt_crypto_p256_keygen with the node's RNG (tests inject keys). */
    mt_err (*opkey_gen)(void *ctx, uint8_t priv[MT_P256_SCALAR_LEN], uint8_t pub[MT_P256_POINT_LEN]);
    /* A SetUTCTime command was accepted: the node's time is now `matter_us` (Matter epoch us) with the given
     * granularity and source. The port may mirror it into its RTC / SNTP view. Not called for mt_root_set_utc().
     * May be NULL. */
    void (*utc_set)(void *ctx, uint64_t matter_us, uint8_t granularity, uint8_t source);
} mt_root_ops;

typedef struct {
    const mt_root_ops *ops;
    void *ctx;                          /* passed to every op */
    mt_fabric_table *fabrics;           /* the node's table (committed + pending) */
    mt_rng *rng;                        /* the node's DRBG (CSR signature, key generation) */
    const mt_root_creds *creds;
    mt_basic *basic;                    /* SetRegulatoryConfig sets its Location (11.10.7.4); may be NULL */
    const mt_kv_ops *kv;                /* RegulatoryConfig record; NULL = not persisted */
    uint16_t kv_key;                    /* e.g. MT_FKEY(0, 0x21) */
    uint8_t location_cap;               /* LocationCapability, MT_REG_*; Apple Home accepts IndoorOutdoor */
    mt_buf scratch;                     /* >= MT_ROOT_SCRATCH bytes, used only during a call */
} mt_root_cfg;

/* Staged state owned by another endpoint-0 cluster (Network Commissioning's Wi-Fi). CommissioningComplete calls
 * commit() after the node's commit op and before the fabric commit (Wi-Fi first, so a power cut never
 * leaves a fabric without a network); commit persists the change and keeps it staged. Non-MT_OK = FAILURE, the
 * fail-safe stays armed. If the fabric commit then fails, undo() puts the persisted state back (still staged, so
 * the eventual expiry reverts the station as 11.10.7.2 asks); if it succeeds, done() forgets the stage. Fail-safe
 * expiry calls revert() after the fabric table rolled back; revert must not answer an IM request synchronously (it
 * can run inside another invoke). Any may be NULL. */
typedef struct {
    mt_err (*commit)(void *ctx, uint8_t fabric);
    void (*undo)(void *ctx);
    void (*done)(void *ctx);
    void (*revert)(void *ctx);
    void *ctx;
} mt_root_stage;

typedef struct {
    bool valid;                         /* false until a time was set (UTCTime null, Granularity None) */
    bool local;                         /* set by the device itself (mt_root_set_utc), not by a commissioner */
    uint8_t granularity, source;
    uint64_t us;                        /* Matter epoch us at ref_ms */
    uint32_t ref_ms;                    /* now_ms() when `us` was valid; mt_root_poll / reads advance both */
} mt_root_time;

typedef struct mt_root {
    mt_root_cfg c;
    mt_root_stage stage;                /* mt_root_set_stage */
    mt_dm *dm;                          /* from mt_root_bind_dm: change marking of all endpoint-0 clusters, device
                                         * types, deferred Network Commissioning answers (dm->im) */
    mt_failsafe fs;
    uint64_t breadcrumb;
    uint8_t regulatory;                 /* RegulatoryConfig */
    mt_root_time time;
    mt_dm_cluster gencomm, opcreds, acl, gkm, timesync; /* list these in endpoint 0 */
} mt_root;

/* MT_ERR_INVALID for a missing op/table/RNG/credential, a short scratch buffer or a bad location_cap.
 * RegulatoryConfig is loaded from kv (default: location_cap, or Indoor when that is IndoorOutdoor). */
mt_err mt_root_init(mt_root *r, const mt_root_cfg *cfg);
void mt_root_bind_dm(mt_root *r, mt_dm *dm);
void mt_root_set_stage(mt_root *r, const mt_root_stage *st);  /* copied */

/* The node's UTC time. Unknown after boot until a SetUTCTime command or mt_root_set_utc() sets it; it then runs
 * on the node clock (mt_root_ops.now_ms), so mt_root_poll() (or any of these) must run at least every ~24 days. */
/* Sets *matter_us and returns true, or false while the time is unknown. */
bool mt_root_utc_us(mt_root *r, uint64_t *matter_us);
/* Matter epoch seconds for certificate validity checks (mt_case_init `now`, mt_fabric_add_noc `now`):
 * 0 = unknown, which skips the checks. A time before 2000-01-01 00:00:01 also reads 0. Saturates at UINT32_MAX. */
uint32_t mt_root_utc_now(mt_root *r);
/* The device learned the time itself (SNTP, RTC): replaces the current one unconditionally and marks the cluster
 * changed. `source` is MT_TIME_SRC_*, `granularity` MT_TIME_GRAN_* (not NONE). MT_ERR_INVALID otherwise. */
mt_err mt_root_set_utc(mt_root *r, uint64_t matter_us, uint8_t granularity, uint8_t source);

/* Expires the fail-safe when due. Returns ms until the deadline, UINT32_MAX when disarmed. */
uint32_t mt_root_poll(mt_root *r);
/* Ends an armed fail-safe now, as on timer expiry (no-op when disarmed): mt_fabric_abort, breadcrumb 0,
 * MT_ROOT_EV_FAILSAFE_EXPIRED. The node may call it too, e.g. when the commissioning PASE session is lost. */
void mt_root_failsafe_expire(mt_root *r);
static inline bool mt_root_failsafe_armed(const mt_root *r) { return r->fs.armed; }
/* Arms a disarmed fail-safe for `fabric` (0 = no accessing fabric yet) for `secs` seconds, as ArmFailSafe would
 * (same cumulative limit); false (nothing changed) if it is already armed or secs is 0. The node calls it when a
 * PASE session is established (chip v1.3 CommissioningWindowManager::OnSessionEstablished arms 60 s), so the
 * session's implicit Administer is bounded by the fail-safe from the start. */
bool mt_root_failsafe_arm(mt_root *r, uint8_t fabric, uint16_t session, uint16_t secs);
#define MT_ROOT_PASE_FAILSAFE_S 60

/* ---- access control (spec 6.6.6) ---- */

/* Does `s` hold `priv` on (endpoint, cluster)? PASE: implicit Administer. CASE: an entry of the session's fabric
 * (committed or pending) with auth mode CASE, a privilege granting `priv` (View < Operate < Manage < Administer,
 * ProxyView only from ProxyView or Administer), a matching subject (node ID, or CAT with the same identifier and
 * a version <= the session's) or none, and a matching target (cluster/endpoint/device type on `node`) or none.
 * Group auth is not supported (false). `node` may be NULL (device-type targets never match). */
bool mt_acl_check(const mt_fabric_table *t, const mt_dm_node *node, const mt_root_session *s, uint16_t endpoint,
                  uint32_t cluster, uint8_t priv);
/* mt_dm_cfg.access adapter; ctx = the mt_root. CATs come from mt_root_ops.session. */
bool mt_root_access(void *ctx, const mt_im_subject *s, uint16_t endpoint, uint32_t cluster, uint8_t priv);

#endif
