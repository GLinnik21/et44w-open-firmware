/* Matter node: the composition layer. Wires matter-xchg to PASE/CASE (Secure Channel) and the Interaction Model,
 * owns the commissioning window, the fail-safe side effects, the policy for unsecured traffic, the mDNS record set
 * and endpoint 0 (Descriptor, Access Control, Basic Information, General Commissioning, Network Commissioning,
 * General Diagnostics, Administrator Commissioning, Operational Credentials, Group Key Management) plus optional
 * application endpoints. Pure C11, no allocation, single threaded: call everything from the Matter task. The
 * platform is reached only through mt_node_ports.
 *
 * Secure Channel (protocol 0, spec 4.11-4.14):
 *  - One handshake (PASE or CASE) at a time; a second PBKDFParamRequest or Sigma1 gets a BUSY StatusReport. Each
 *    handshake has a fresh random session ID (never one in use or the previous one) and a 60 s deadline. An
 *    attempt whose initiator has sent nothing for MT_NODE_STALL_MS is dropped when a new one asks, so a peer that
 *    opens a handshake and goes quiet cannot hold the slot; to keep it, it has to make a passcode guess (Pake1),
 *    and those are counted.
 *  - PASE runs only while a commissioning window is open, with that window's verifier (the device's own for the
 *    boot window, the controller's for an enhanced window). A new PASE session replaces an older one.
 *  - Brute-force limit: a PASE attempt that reached Pake2 lets the initiator check its passcode guess, so every
 *    such attempt that ends without a session counts as a failure. MT_NODE_MAX_FAILED_ATTEMPTS failures close
 *    the window; opening it again starts a new count. CASE attempts never count.
 *  - CASE (responder): Sigma1's destination ID is matched over the committed fabrics and the pending fail-safe
 *    fabric, so the commissioner can reach the new fabric before CommissioningComplete (the
 *    commissioner's CASE step).
 *  - CloseSession on a secure session closes it.
 *  - Unsecured traffic cannot starve secure sessions: BUSY / failure reports are sent unreliably and their
 *    exchanges closed at once, and a handshake only starts while MT_NODE_XC_RESERVE exchanges and
 *    MT_NODE_TXBUF_RESERVE frame buffers stay free.
 * Interaction Model (protocol 1): secure sessions only. Access is the Access Control check of matter-root (PASE is
 * an implicit Administer, CASE subjects need an ACL entry of their fabric).
 *
 * Commissioning: the window is open at boot while no fabric is committed (cfg.boot_window_s, 0 = until
 * commissioned) and again when the last fabric is removed; Administrator Commissioning opens enhanced windows.
 * CommissioningComplete closes the window; the PASE sessions are closed once the response is acknowledged. The
 * fail-safe lives in matter-root; on its expiry the node closes the CASE sessions of the discarded fabric, unbinds
 * the PASE session from it and drops its mDNS record (staged Wi-Fi is reverted by Network Commissioning). Sessions
 * of a removed fabric (RemoveFabric) are likewise closed after the response is acknowledged.
 *
 * BLE (Matter over BTP, spec 4.17-4.19): with ports.ble_send set, BLE follows the BASIC
 * window (the boot window, and the one that reopens when the last fabric goes; never an enhanced window), for at
 * most cfg.ble_window_s. The port advertises while told to (ports.ble_window) and reports GATT events through
 * mt_node_on_ble; the node runs the BTP engine, the CCCD gate (nothing is indicated before the central subscribes
 * to C2), one indication in flight at a time and a handshake timeout. A BLE disconnect closes the sessions over
 * BTP with MT_XCHG_END_TRANSPORT, which leaves the fail-safe armed (the commissioner continues over CASE after
 * ConnectNetwork). After the window, a connection carrying no secure session is dropped; one that does is kept
 * until it disconnects. CommissioningComplete turns BLE off for good before anything is written to flash
 * (on this radio a flash write stalls BLE timing); a later window asks the port to turn it on again (the AmebaZ2 port reboots for that).
 *
 * Persistence (ports.kv, required): fabrics (matter-fabric), NodeLabel/Location (MT_NODE_KEY_BASIC), the
 * RegulatoryConfig (MT_NODE_KEY_REGULATORY) and the BOOT record (MT_NODE_KEY_BOOT: reboot count and event-number
 * epoch, written once per init). */
#ifndef MT_NODE_H
#define MT_NODE_H

#include "mt_admincomm.h"
#include "mt_btp.h"
#include "mt_case.h"
#include "mt_core.h"
#include "mt_crypto.h"
#include "mt_dm.h"
#include "mt_fabric.h"
#include "mt_gendiag.h"
#include "mt_im.h"
#include "mt_netcomm.h"
#include "mt_pase.h"
#include "mt_root.h"
#include "mt_root_comm.h"
#include "mt_xchg.h"

#ifndef MT_NODE_IM_BUF_MAX
#define MT_NODE_IM_BUF_MAX MT_XCHG_MAX_PAYLOAD /* largest IM payload (chunk) */
#endif
#define MT_NODE_IM_BUF_MIN 128
#define MT_NODE_MAX_EXTRA_EPS 2
#define MT_NODE_ATTEMPT_MS 60000     /* handshake (PASE/CASE) establishment timeout */
#define MT_NODE_BUSY_WAIT_MS 5000    /* minimum wait announced in a BUSY report */
#ifndef MT_NODE_STALL_MS
#define MT_NODE_STALL_MS 15000       /* an attempt whose initiator is silent this long gives way to a new one */
#endif
#ifndef MT_NODE_MAX_FAILED_ATTEMPTS
#define MT_NODE_MAX_FAILED_ATTEMPTS 20 /* failed PASE guesses per window: chip v1.3
                                         * CommissioningWindowManager.cpp kMaxFailedCommissioningAttempts */
#endif
#define MT_NODE_XC_RESERVE 2         /* exchanges an unsecured attempt must leave free */
#define MT_NODE_TXBUF_RESERVE 1      /* frame buffers an unsecured reply must leave free */
#define MT_NODE_CLOSE_GRACE_MS 10000 /* a session marked for closing waits at most this long for its last ack */
#define MT_NODE_EPOCH_STEP 0x10000u  /* event numbers reserved per boot (BOOT record) */
#define MT_NODE_N_ROOT_CLUSTERS 10

/* kv records of the node (index 0 = node-level, see MT_FKEY). */
#define MT_NODE_KEY_BASIC 0x0020u      /* NodeLabel + Location (matter-root Basic Information) */
#define MT_NODE_KEY_REGULATORY 0x0021u /* RegulatoryConfig (matter-root General Commissioning) */
#define MT_NODE_KEY_BOOT 0x0023u       /* {1: reboot count, 2: event epoch} */

typedef mt_xchg_addr mt_node_addr;

/* The passcode-derived PASE verifier of the boot window (never the passcode) and the attestation material.
 * Spans must outlive the node. */
typedef struct {
    uint8_t w0[MT_P256_SCALAR_LEN];
    uint8_t l[MT_P256_POINT_LEN];
    mt_span salt;           /* 16..32 bytes */
    uint32_t iterations;    /* 1000..100000 */
    uint16_t discriminator; /* 12 bits, advertised while the boot window is open */
    mt_root_creds attest;   /* DAC, PAI, CD and the DAC signer (spec 6.2) */
} mt_node_credentials;

typedef struct {
    void *ctx;              /* passed to every port function, including the netctl ops */
    uint32_t (*now_ms)(void *ctx);
    void (*udp_send)(void *ctx, const mt_node_addr *to, mt_span frame);
    /* Fill out with entropy; 0 on success (mt_entropy_fn contract). */
    int (*entropy)(void *ctx, uint8_t *out, size_t len);
    const mt_kv_ops *kv;                  /* required: fabric certificates and keys live only in storage */
    const mt_node_credentials *cred;
    /* Wi-Fi station behind Network Commissioning; NULL = no Network Commissioning cluster. Results of connect and
     * scan come back through mt_node_net_connect_done / mt_node_net_scan_done. */
    const mt_netctl_ops *net;
    bool (*iface)(void *ctx, mt_gendiag_iface *out);   /* General Diagnostics NetworkInterfaces; may be NULL */
    /* The mDNS record set changed (window opened/closed, fabric added/removed/updated): re-read it with
     * mt_node_mdns_count / mt_node_mdns_get and re-advertise. Also called once at the end of init. May be NULL. */
    void (*mdns_changed)(void *ctx);
    /* A commissioner set the node's UTC time (SetUTCTime accepted): Matter epoch microseconds (unix us minus
     * 946684800e6), a MT_TIME_GRAN_* and MT_TIME_SRC_*. The port may use it for its RTC / SNTP view. May be NULL. */
    void (*utc_set)(void *ctx, uint64_t matter_us, uint8_t granularity, uint8_t source);
    /* BLE (all three or none). ble_send indicates one BTP packet on C2 (the port copies it); true = accepted, and
     * an MT_NODE_BLE_SENT event follows once the central confirmed it. ble_close drops the connection
     * (MT_NODE_BLE_DISCONNECTED follows). ble_window(open): advertise while open; open = false turns BLE off and
     * returns only once the radio is off (also dropping a connection, without a DISCONNECTED event). None of them
     * may call back into the node. */
    bool (*ble_send)(void *ctx, mt_span pkt);
    void (*ble_close)(void *ctx);
    void (*ble_window)(void *ctx, bool open);
    /* Test hook: operational key pair for CSRRequest. NULL = generated with the node's DRBG. */
    mt_err (*opkey_gen)(void *ctx, uint8_t priv[MT_P256_SCALAR_LEN], uint8_t pub[MT_P256_POINT_LEN]);
    /* Debug hook: every Interaction Model message received (tx = false) or sent (tx = true, err = the send
     * result) on a secure session, with its IM opcode and payload length. The plaintext is withheld on purpose:
     * it carries secrets (Wi-Fi passphrase, IPK, PAKE verifier). May be NULL. */
    void (*im_trace)(void *ctx, bool tx, uint16_t session, uint8_t opcode, size_t len, mt_err err);
} mt_node_ports;

typedef struct {
    mt_node_ports ports;                  /* copied */
    const mt_basic_cfg *basic;            /* must outlive the node; its vendor/product ids go into VP */
    uint16_t im_buf_len;                  /* IM chunk size, MT_NODE_IM_BUF_MIN..MT_NODE_IM_BUF_MAX; 0 = max */
    const mt_dm_endpoint *extra_eps;      /* application endpoints, copied; their clusters must outlive the node */
    uint8_t n_extra_eps;                  /* <= MT_NODE_MAX_EXTRA_EPS */
    /* First event number of the first boot (no BOOT record yet); later boots take it from the BOOT record, so
     * event numbers grow across reboots (controllers filter older numbers out). 0 = start at 1. */
    uint64_t event_base;
    uint32_t boot_window_s;               /* commissioning window at boot when uncommissioned; 0 = no timeout */
    uint32_t ble_window_s;                /* BLE part of a BASIC window; 0 = as long as the window */
    uint8_t boot_reason;                  /* General Diagnostics BootReason, MT_BOOT_* */
    uint32_t mrp_idle_ms, mrp_active_ms;  /* our MRP intervals (handshakes, SII/SAI); 0 = spec defaults */
    uint16_t device_type;                 /* primary device type for the DT TXT key; 0 = omitted */
    const char *device_name;              /* DN TXT key (<= 32 bytes); NULL = omitted */
    uint16_t pairing_hint;                /* PH TXT key (PairingHint bitmap, spec 4.3.1; chip default 33) */
    uint8_t location_cap;                 /* General Commissioning LocationCapability, MT_REG_* */
    bool net_replace_when_full;           /* Network Commissioning: a new SSID replaces the one slot (recommissioning) */
} mt_node_cfg;

typedef struct {                          /* the one handshake in progress */
    uint8_t kind;                         /* 0 none, MT_SESS_PASE or MT_SESS_CASE */
    bool guessed;                         /* PASE: Pake2 went out, the initiator could test a passcode guess */
    mt_xchg_xchg *xc;                     /* its unsecured exchange */
    uint32_t deadline;
    uint32_t last_rx;                     /* the initiator's last message (MT_NODE_STALL_MS) */
    union {
        struct { mt_pase_config cfg; mt_pase m; } pase;
        mt_case cas;
    } u;
} mt_node_attempt;

typedef struct {
    mt_xchg_xchg *xc;                     /* NULL = unused */
    uint16_t handle;                      /* what IM calls the exchange */
    bool keep;                            /* IM asked to keep it open for a reply */
} mt_node_ex;

typedef struct {                          /* per xchg session slot: what the root ops need besides mt_xchg_session */
    uint16_t local_id;                    /* the session this belongs to (0 = none) */
    uint8_t challenge[MT_ROOT_CHALLENGE_LEN];
    uint32_t cats[MT_CERT_MAX_CATS];
    uint8_t n_cats;
    bool doomed;                          /* close once its exchanges are done (or at doom_deadline) */
    bool lost;                            /* its BLE link went away: close now, as a transport loss */
    uint32_t doom_deadline;
} mt_node_sess;

typedef struct {                          /* the commissioning window */
    uint8_t kind;                         /* MT_WINDOW_NOT_OPEN / _ENHANCED / _BASIC */
    bool timed;
    uint32_t deadline;
    uint16_t discriminator;
    uint8_t w0[MT_P256_SCALAR_LEN], l[MT_P256_POINT_LEN];
    uint8_t salt[MT_ADMIN_SALT_MAX];
    uint8_t salt_len;
    uint32_t iterations;
    uint8_t instance[8];                  /* random commissionable instance name of this window */
} mt_node_window;

#ifndef MT_NODE_BLE_TXQ
#define MT_NODE_BLE_TXQ 2                 /* outgoing BTP messages queued behind the one being segmented */
#endif
#define MT_NODE_BLE_HS_MS 15000           /* connect -> handshake answered and C2 subscribed, else disconnect */
#define MT_NODE_BLE_CONFIRM_MS 30000      /* an indication unconfirmed this long drops the link (ATT timeout) */

typedef enum {
    MT_NODE_BLE_CONNECTED,                /* a central connected (advertising stopped) */
    MT_NODE_BLE_MTU,                      /* val = negotiated ATT MTU */
    MT_NODE_BLE_SUBSCRIBED,               /* CCCD of C2 written with indications on */
    MT_NODE_BLE_UNSUBSCRIBED,             /* ... off */
    MT_NODE_BLE_WRITE,                    /* data = one write on C1 */
    MT_NODE_BLE_SENT,                     /* the indication from ble_send: val 0 = confirmed, else failed */
    MT_NODE_BLE_DISCONNECTED,
} mt_node_ble_ev;

typedef enum {                            /* why the node last asked the port to drop the link */
    MT_NODE_BLE_CLOSE_NONE,
    MT_NODE_BLE_CLOSE_BTP_CLOSED,         /* the BTP engine closed (protocol error or its timers) */
    MT_NODE_BLE_CLOSE_BTP_SEND,           /* the engine refused a queued message */
    MT_NODE_BLE_CLOSE_PORT_SEND,          /* ble_send failed */
    MT_NODE_BLE_CLOSE_QUEUE,              /* outgoing queue full or message too large */
    MT_NODE_BLE_CLOSE_RX,                 /* a write the engine rejected */
    MT_NODE_BLE_CLOSE_LATE,               /* connected after BLE was asked off */
    MT_NODE_BLE_CLOSE_UNSUB,              /* C2 unsubscribed after the handshake */
    MT_NODE_BLE_CLOSE_NACK,               /* an indication failed */
    MT_NODE_BLE_CLOSE_HS_TIMEOUT,         /* no handshake + subscription within MT_NODE_BLE_HS_MS */
    MT_NODE_BLE_CLOSE_CONFIRM_TIMEOUT,    /* an indication unconfirmed for MT_NODE_BLE_CONFIRM_MS */
    MT_NODE_BLE_CLOSE_IDLE,               /* the window ended with no session on the link */
} mt_node_ble_close;

typedef struct {
    bool want;                            /* the BLE part of a BASIC window is open */
    bool on;                              /* ble_window(true) was the last call */
    bool timed;
    bool conn, subscribed, engine, in_flight, closing, q_sending;
    uint8_t close_why;                    /* mt_node_ble_close, kept until the next connect */
    uint16_t att_mtu;
    uint32_t deadline, conn_at, sent_at;
    uint8_t q_head, q_n;
    uint16_t q_len[MT_NODE_BLE_TXQ];
    mt_btp btp;
    uint8_t rx[MT_XCHG_MAX_FRAME];
    uint8_t q[MT_NODE_BLE_TXQ][MT_XCHG_MAX_FRAME];
    uint8_t pkt[MT_BTP_MAX_FRAG];
} mt_node_ble;

typedef struct mt_node {
    mt_node_ports p;
    const mt_basic_cfg *basic_cfg;
    uint16_t device_type, pairing_hint;
    const char *device_name;
    uint32_t mrp_idle_ms, mrp_active_ms;
    mt_rng rng;
    mt_xchg xchg;
    mt_xchg_proto sc_proto, im_proto;
    mt_im im;
    mt_dm dm;
    mt_basic basic;
    mt_fabric_table fabrics;
    mt_root root;
    mt_netcomm netcomm;
    mt_gendiag gendiag;
    mt_admin admin;
    mt_root_ops root_ops;
    mt_admin_ops admin_ops;
    mt_case_config case_cfg;
    mt_dm_node dmnode;
    mt_dm_endpoint eps[1 + MT_NODE_MAX_EXTRA_EPS];
    const mt_dm_cluster *root_clusters[MT_NODE_N_ROOT_CLUSTERS];
    mt_dm_devtype root_types[1];
    uint8_t im_buf[MT_NODE_IM_BUF_MAX];
    uint8_t sc_buf[MT_CASE_OUT_MIN];      /* Secure Channel reply (Sigma2 is the largest) */
    uint8_t work[MT_CASE_WORK];           /* CASE work space; root / netcomm / fabric-load scratch (never nested) */
    mt_node_attempt att;
    /* Handshake counters for the port's log: CASE Sigma1s taken, CASE attempts that failed, handshakes refused
     * (busy with another, or short of memory). */
    uint32_t case_started, case_failed, sc_refused;
    uint32_t rng_failed;                  /* transport random requests the DRBG refused (entropy source failing) */
    uint64_t rng_fallback;                /* their fallback stream's state, seeded from the DRBG at init */
    mt_node_ex ex[MT_XCHG_N_EXCHANGES];
    mt_node_sess sess[MT_XCHG_N_SESSIONS];
    mt_node_window win;
    uint16_t next_handle;
    uint16_t last_session_id;
    uint16_t reboot_count;
    uint8_t failed_attempts;              /* failed guesses in this commissioning window */
    uint32_t boot_window_s, ble_window_s;
    mt_node_ble ble;
} mt_node;

/* MT_ERR_INVALID for a bad config; MT_ERR_CRYPTO if the RNG fails. */
mt_err mt_node_init(mt_node *n, const mt_node_cfg *cfg);

/* One received datagram. buf is decrypted in place (and so clobbered). */
void mt_node_on_udp(mt_node *n, const mt_node_addr *from, uint8_t *buf, size_t len);

/* Runs due timers; returns ms until the next one (UINT32_MAX = none). */
uint32_t mt_node_poll(mt_node *n);

/* Commissioning window with the device's own verifier (the boot window). Closing it aborts a PASE attempt in
 * progress; existing sessions stay. Opening a closed window resets the failed-attempt count. timeout_s 0 = none. */
void mt_node_open_window(mt_node *n, uint32_t timeout_s);
void mt_node_set_window(mt_node *n, bool open);       /* open = mt_node_open_window(n, 0) */
bool mt_node_window_open(const mt_node *n);
bool mt_node_failsafe_armed(const mt_node *n);
/* Factory reset of the node's part: ends a fail-safe, removes every fabric (persisted) and closes their sessions.
 * No window opens: the caller erases the rest of its state and reboots, and the boot opens it. */
void mt_node_factory_reset(mt_node *n);         /* a commissioner holds the fail-safe (ArmFailSafe) */
/* The device learned the UTC time itself (SNTP, RTC): Matter epoch microseconds (unix us minus 946684800e6),
 * MT_TIME_GRAN_* (not NONE) and MT_TIME_SRC_*. Replaces any time a commissioner set and starts certificate
 * validity checks (CASE, AddNOC, UpdateNOC) if it was unknown; does not call ports.utc_set. MT_ERR_INVALID for a
 * bad granularity or source. */
mt_err mt_node_set_utc(mt_node *n, uint64_t matter_us, uint8_t granularity, uint8_t source);
/* Matter epoch seconds, 0 = unknown (no SetUTCTime / mt_node_set_utc since boot). */
uint32_t mt_node_utc_now(mt_node *n);

/* One BLE event from the port (see mt_node_ble_ev). Ignored when ports.ble_send is NULL. */
void mt_node_on_ble(mt_node *n, mt_node_ble_ev ev, mt_span data, uint16_t val);
bool mt_node_ble_on(const mt_node *n);              /* the port was told to run BLE */
bool mt_node_ble_connected(const mt_node *n);
mt_node_ble_close mt_node_ble_close_why(const mt_node *n);   /* for the port's log */

/* Network Commissioning results from the port (see mt_netcomm_connect_done / mt_netcomm_scan_done). */
void mt_node_net_connect_done(mt_node *n, uint8_t status, const int32_t *err);
void mt_node_net_scan_done(mt_node *n, uint8_t status);

/* ---- mDNS record set (spec 4.3) ---- */
#define MT_NODE_MDNS_MAX (1 + MT_FABRIC_MAX + 1)  /* commissionable + committed fabrics + a pending one */
#define MT_NODE_MDNS_SUB_MAX 4
#define MT_NODE_MDNS_TXT_MAX 10
typedef struct {
    bool operational;                     /* _matter._tcp (operational) or _matterc._udp (commissionable) */
    char instance[34];                    /* "<CFID>-<NodeID>" (16 hex digits each, upper case) or 16 hex digits */
    uint8_t n_sub, n_txt;
    char sub[MT_NODE_MDNS_SUB_MAX][20];   /* subtypes without the "._sub" part: "_L3840", "_S15", "_CM", "_I<CFID>" */
    char txt[MT_NODE_MDNS_TXT_MAX][40];   /* "key=value" */
} mt_node_mdns_rec;
unsigned mt_node_mdns_count(const mt_node *n);
/* Record `idx` (0 .. count-1): the commissionable record first while a window is open, then one operational
 * record per fabric (committed, or pending under the fail-safe). false past the end. */
bool mt_node_mdns_get(const mt_node *n, unsigned idx, mt_node_mdns_rec *out);

/* Diagnostics and tests. */
bool mt_node_pase_busy(const mt_node *n);           /* a PASE attempt is in progress */
bool mt_node_handshake_busy(const mt_node *n);      /* a PASE or CASE handshake is in progress */
unsigned mt_node_session_count(const mt_node *n, mt_sess_kind kind);
uint16_t mt_node_reboot_count(const mt_node *n);

#endif
