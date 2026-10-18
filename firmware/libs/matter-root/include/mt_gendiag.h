/* General Diagnostics cluster (0x33, spec 1.3 section 11.12, revision 2), endpoint 0, minimal.
 *
 *  - Attributes: NetworkInterfaces (one Wi-Fi interface from mt_gendiag_ops.iface), RebootCount, UpTime (seconds
 *    since boot), BootReason, TestEventTriggersEnabled. Not served (all optional): TotalOperationalHours,
 *    ActiveHardwareFaults/ActiveRadioFaults/ActiveNetworkFaults and the fault/BootReason events.
 *  - Commands: TestEventTrigger (Manage; refused with CONSTRAINT_ERROR unless cfg.enable_key is set, non-zero and
 *    matches, as chip with no test-event delegate), TimeSnapshot (-> TimeSnapshotResponse: system time since boot
 *    in ms, POSIX time null: there is no Time Synchronization).
 * Rules follow connectedhomeip v1.3-branch general-diagnostics-server.cpp; ids and conformance from the 1.3 data
 * model (DiagnosticsGeneral.xml). Pure C11, no allocation. */
#ifndef MT_GENDIAG_H
#define MT_GENDIAG_H

#include "mt_dm.h"

#define MT_GENDIAG_CLUSTER_ID 0x0033u
#define MT_GENDIAG_KEY_LEN 16        /* TestEventTrigger EnableKey */
#define MT_GENDIAG_MAX_V4 2
#define MT_GENDIAG_MAX_V6 4          /* link-local + global/ULA addresses */

/* BootReasonEnum (11.12.5.1). */
enum { MT_BOOT_UNSPECIFIED = 0, MT_BOOT_POWER_ON = 1, MT_BOOT_BROWN_OUT = 2, MT_BOOT_SW_WATCHDOG = 3,
       MT_BOOT_HW_WATCHDOG = 4, MT_BOOT_SW_UPDATE = 5, MT_BOOT_SW_RESET = 6 };
/* InterfaceTypeEnum (11.12.5.3). */
enum { MT_IFACE_UNSPECIFIED = 0, MT_IFACE_WIFI = 1, MT_IFACE_ETHERNET = 2, MT_IFACE_CELLULAR = 3,
       MT_IFACE_THREAD = 4 };

/* The state of the one network interface (NetworkInterface struct). */
typedef struct {
    char name[17];                       /* e.g. "wlan0", NUL-terminated, <= 16 */
    bool operational;
    uint8_t hw[8];                       /* MAC, 6 or 8 bytes */
    uint8_t hw_len;
    uint8_t n4, n6;
    uint8_t v4[MT_GENDIAG_MAX_V4][4];
    uint8_t v6[MT_GENDIAG_MAX_V6][16];
    uint8_t type;                        /* MT_IFACE_* */
} mt_gendiag_iface;

typedef struct {
    void *ctx;
    uint32_t (*now_ms)(void *ctx);
    /* Current state of the interface; false = unavailable (an empty list). May be NULL. */
    bool (*iface)(void *ctx, mt_gendiag_iface *out);
    /* Run test event `trigger`; non-MT_OK becomes INVALID_COMMAND. May be NULL. */
    mt_err (*trigger)(void *ctx, uint64_t trigger);
    const uint8_t *enable_key;           /* 16 bytes, NULL or all zero = test events off; must outlive the cluster */
    uint16_t reboot_count;               /* the port keeps the persisted counter and passes this boot's value */
    uint8_t boot_reason;                 /* MT_BOOT_* */
} mt_gendiag_cfg;

typedef struct mt_gendiag {
    mt_gendiag_cfg c;
    uint64_t up_ms;                      /* accumulated; see mt_gendiag_tick */
    uint32_t last_ms;
    mt_dm_cluster cluster;               /* list in endpoint 0 */
} mt_gendiag;

/* MT_ERR_INVALID without a clock. */
mt_err mt_gendiag_init(mt_gendiag *g, const mt_gendiag_cfg *cfg);
/* UpTime accumulates 32-bit clock deltas on every read; call this at least every 24 days (the node's poll loop
 * does) so the clock cannot wrap unseen. */
void mt_gendiag_tick(mt_gendiag *g);
/* The interface changed (link up/down, address): mark NetworkInterfaces dirty for subscriptions. */
void mt_gendiag_iface_changed(mt_gendiag *g, mt_dm *dm);

#endif
