/* matter-dm internals shared by dm.c, dm_descriptor.c and dm_check.c. */
#ifndef MT_DM_PRIV_H
#define MT_DM_PRIV_H

#include "mt_dm.h"

#define DM_GLOBAL_FIRST 0xFFF8u
#define DM_GLOBAL_LAST 0xFFFDu

typedef struct {
    const mt_dm_endpoint *ep;
    const mt_dm_cluster *cl;
    uint8_t cidx;                    /* dense cluster-instance index over the whole node */
} dm_loc;

static inline bool dm_is_global(uint32_t id) { return id >= DM_GLOBAL_FIRST && id <= DM_GLOBAL_LAST; }

bool dm_locate(const mt_dm_node *node, uint16_t endpoint, uint32_t cluster, dm_loc *out);

#endif
