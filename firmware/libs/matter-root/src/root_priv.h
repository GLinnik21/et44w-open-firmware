/* Internal to matter-root: helpers shared by the commissioning cluster files. */
#ifndef MT_ROOT_PRIV_H
#define MT_ROOT_PRIV_H

#include <string.h>
#include "mt_root_comm.h"

#define CTX(n) mt_tlv_ctx(n)
#define TAG_FABRIC_INDEX 254 /* FabricIndex field of fabric-scoped structs (spec 7.13.6) */

/* The invoking session; false when the node no longer knows it. */
bool root_session(mt_root *r, uint16_t session, mt_root_session *out);

/* Is the fail-safe armed for this accessing fabric? (chip FailSafeContext::IsFailSafeArmed(index)) */
static inline bool root_fs_armed_for(const mt_root *r, uint8_t fabric) { return r->fs.armed && r->fs.fabric == fabric; }

/* Arm (or re-arm) the fail-safe for `fabric`/`session` for `secs` (> 0) seconds, capped by the cumulative limit
 * set at the first arm (11.10.7.2). */
void root_fs_arm(mt_root *r, uint8_t fabric, uint16_t session, uint16_t secs);

static inline void root_event(mt_root *r, mt_root_event ev, uint8_t fabric, uint16_t session, uint8_t flags)
{
    if (r->c.ops->event) r->c.ops->event(r->c.ctx, ev, fabric, session, flags);
}

/* An endpoint-0 cluster's attributes changed: bump its data version and mark the path dirty (through the dm bound
 * with mt_root_bind_dm; no-op before that). */
void root_changed(mt_root *r, uint32_t cluster, uint32_t attr);

/* Set the Breadcrumb attribute (commands carrying an optional Breadcrumb field call this on success). */
void root_set_breadcrumb(mt_root *r, uint64_t v);

/* Persist RegulatoryConfig (no-op without kv). */
mt_err root_save_regulatory(mt_root *r, uint8_t v);

/* Per-cluster setup (called by mt_root_init). */
void root_gencomm_init(mt_root *r);
void root_opcreds_init(mt_root *r);
void root_acl_init(mt_root *r);
void root_gkm_init(mt_root *r);
void root_timesync_init(mt_root *r);
/* Fold the node-clock time elapsed since the last call into the UTC time (keeps the 32-bit clock from wrapping). */
void root_time_advance(mt_root *r);

#endif
