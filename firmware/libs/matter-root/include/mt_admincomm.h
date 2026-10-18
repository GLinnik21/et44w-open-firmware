/* Administrator Commissioning cluster (0x3C, spec 1.3 section 11.19, revision 1, no Basic feature), endpoint 0.
 *
 *  - Attributes: WindowStatus, AdminFabricIndex, AdminVendorId (the last two null unless an administrator opened
 *    the window with this cluster).
 *  - Commands (all Administer, timed): OpenCommissioningWindow (enhanced commissioning: the controller supplies
 *    the PAKE verifier, discriminator, iterations and salt), RevokeCommissioning. OpenBasicCommissioningWindow is
 *    not offered (feature Basic off).
 * The window itself belongs to the node (PASE config, mDNS, timer): mt_admin_ops opens and closes it. The node
 * calls mt_admin_window_changed when a window opens or closes on its own (boot window, timeout, commissioning
 * complete) and mt_admin_fabric_removed on MT_ROOT_EV_FABRIC_REMOVED.
 * Rules follow connectedhomeip v1.3-branch administrator-commissioning-server.cpp. Pure C11, no allocation. */
#ifndef MT_ADMINCOMM_H
#define MT_ADMINCOMM_H

#include "mt_root_comm.h"

#define MT_ADMIN_CLUSTER_ID 0x003Cu

/* CommissioningWindowStatusEnum (11.19.5.1). */
enum { MT_WINDOW_NOT_OPEN = 0, MT_WINDOW_ENHANCED = 1, MT_WINDOW_BASIC = 2 };
/* StatusCode (11.19.6), returned as cluster-specific statuses. */
enum { MT_ADMIN_BUSY = 2, MT_ADMIN_PAKE_PARAMETER_ERROR = 3, MT_ADMIN_WINDOW_NOT_OPEN = 4 };

#define MT_ADMIN_TIMEOUT_MIN_S 180     /* CommissioningTimeout limits (11.19.8.1) */
#define MT_ADMIN_TIMEOUT_MAX_S 900
#define MT_ADMIN_VERIFIER_LEN 97       /* PAKEPasscodeVerifier = w0 (32) || L (65) */
#define MT_ADMIN_ITERATIONS_MIN 1000   /* Spake2p PBKDF limits (spec 3.9) */
#define MT_ADMIN_ITERATIONS_MAX 100000
#define MT_ADMIN_SALT_MIN 16
#define MT_ADMIN_SALT_MAX 32
#define MT_ADMIN_MAX_DISCRIMINATOR 0x0FFF

/* An enhanced window to open. `salt` points into the request buffer: copy it in open(). */
typedef struct {
    uint16_t timeout_s;
    uint16_t discriminator;
    uint8_t w0[32];
    uint8_t l[65];
    mt_span salt;
    uint32_t iterations;
    uint8_t fabric;                    /* the administrator that asked */
    uint16_t vendor_id;                /* its AdminVendorId */
} mt_admin_window;

typedef struct {
    uint8_t (*status)(void *ctx);                           /* MT_WINDOW_* of the node's window right now */
    mt_err (*open)(void *ctx, const mt_admin_window *w);    /* start the ECM window; non-MT_OK = PAKEParameterError */
    void (*close)(void *ctx);                               /* RevokeCommissioning on an open window */
} mt_admin_ops;

typedef struct {
    const mt_admin_ops *ops;
    void *ctx;
    mt_root *root;                     /* fail-safe state, fabric table */
} mt_admin_cfg;

typedef struct mt_admin {
    mt_admin_cfg c;
    uint8_t fabric;                    /* opener of the current ECM window, 0 = none */
    uint16_t vendor_id;
    mt_dm_cluster cluster;             /* list in endpoint 0 */
} mt_admin;

mt_err mt_admin_init(mt_admin *a, const mt_admin_cfg *cfg);   /* MT_ERR_INVALID for a missing op or root */
/* The node's window opened or closed on its own: forget the opener of a closed window and mark the attributes. */
void mt_admin_window_changed(mt_admin *a);
/* A fabric was removed: a window its administrator opened is closed (chip CommissioningWindowManager). */
void mt_admin_fabric_removed(mt_admin *a, uint8_t fabric);

#endif
