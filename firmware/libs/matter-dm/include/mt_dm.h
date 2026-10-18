/* Matter data model (spec 1.3 ch. 7, 9.5): the node is a static const tree of endpoints, clusters and
 * attribute/command descriptors. This lib answers matter-im's mt_im_dm boundary from that tree:
 *  - flat attribute enumeration (wildcard expansion itself is matter-im's job, driven by attr_at);
 *  - the global attributes (ClusterRevision, FeatureMap, AttributeList, AcceptedCommandList,
 *    GeneratedCommandList, and EventList for clusters that declare events);
 *  - the Descriptor cluster, built in (DeviceTypeList, ServerList, ClientList, PartsList);
 *  - one data version per cluster instance, bumped on every successful write or mt_dm_changed();
 *  - dispatch of everything else to the cluster's handler (mt_dm_ops).
 * Enumeration order is table order: endpoints, then clusters, then the cluster's own attributes, then
 * its globals (0xFFF8, 0xFFF9, [0xFFFA], 0xFFFB, 0xFFFC, 0xFFFD). Tables never change at run time, so
 * attr_at indexes are stable (chunked reports resume by index).
 * Pure C11, no allocation. Depends on matter-core, matter-tlv and matter-im (types, mark_dirty). */
#ifndef MT_DM_H
#define MT_DM_H

#include "mt_im.h"

#define MT_DM_MAX_CLUSTERS 32u   /* cluster instances in the node: mt_im_attr.cluster_idx is < 32 */

#define MT_DM_CLUSTER_DESCRIPTOR 0x1Du

/* Global attribute ids (spec 7.13). */
enum { MT_DM_ATTR_GENERATED_CMDS = 0xFFF8, MT_DM_ATTR_ACCEPTED_CMDS = 0xFFF9, MT_DM_ATTR_EVENT_LIST = 0xFFFA,
       MT_DM_ATTR_ATTR_LIST = 0xFFFB, MT_DM_ATTR_FEATURE_MAP = 0xFFFC, MT_DM_ATTR_CLUSTER_REV = 0xFFFD };

/* ---- the static tables ---- */

typedef struct {
    uint32_t id;
    uint8_t flags;                   /* MT_IM_ATTR_* */
    uint8_t read_priv, write_priv;   /* MT_IM_PRIV_*; write_priv 0 = read-only, even with MT_IM_ATTR_WRITABLE */
} mt_dm_attr_def;

typedef struct {
    uint32_t id;
    uint8_t priv;                    /* privilege needed to invoke */
    bool timed;                      /* requires a timed interaction */
} mt_dm_cmd_def;

typedef struct mt_dm mt_dm;
typedef struct mt_dm_endpoint mt_dm_endpoint;
typedef struct mt_dm_cluster mt_dm_cluster;

/* What a handler is told about the instance it serves. */
typedef struct {
    mt_dm *dm;
    const mt_dm_endpoint *ep;
    const mt_dm_cluster *cl;         /* cl->ctx is the cluster's private state */
} mt_dm_at;

/* A cluster's handler. Any member may be NULL (read -> FAILURE, write -> UNSUPPORTED_WRITE,
 * invoke -> UNSUPPORTED_COMMAND). Global attributes never reach the handler. */
typedef struct {
    /* Same contract as mt_im_dm.read: scalars use item 0; lists write item `item` and return
     * MT_ERR_NOT_FOUND past the last; MT_ERR_BUFFER_TOO_SMALL when out of space. */
    mt_err (*read)(const mt_dm_at *at, const mt_im_rctx *rc, uint32_t attr, uint16_t item, mt_tlv_wr *w,
                   mt_tlv_tag tag);
    /* On SUCCESS the DM bumps the data version and marks the attribute dirty. */
    mt_im_status (*write)(const mt_dm_at *at, const mt_im_wctx *wc, uint32_t attr, mt_im_wr_op op,
                          mt_tlv_rd *val);
    /* Same contract as mt_im_dm.invoke. A handler that changes attributes calls mt_dm_changed(). */
    mt_im_status (*invoke)(const mt_dm_at *at, const mt_im_subject *s, uint32_t cmd, mt_tlv_rd *fields,
                           mt_tlv_wr *resp, uint32_t *resp_cmd);
} mt_dm_ops;

struct mt_dm_cluster {
    uint32_t id;
    uint32_t features;               /* FeatureMap */
    uint16_t revision;               /* ClusterRevision */
    uint8_t n_attrs, n_cmds, n_generated, n_events;
    const mt_dm_attr_def *attrs;     /* the cluster's own attributes (no globals) */
    const mt_dm_cmd_def *cmds;       /* accepted commands */
    const uint32_t *generated;       /* response commands the cluster can generate */
    const uint32_t *events;          /* event ids; non-empty adds the EventList attribute */
    const mt_dm_ops *ops;
    void *ctx;
};

/* Element count of a static table, for mt_dm_cluster's n_* fields. */
#define MT_DM_N(a) ((uint8_t)(sizeof (a) / sizeof (a)[0]))

typedef struct {
    uint32_t type;                   /* device type id */
    uint16_t revision;
} mt_dm_devtype;

struct mt_dm_endpoint {
    uint16_t id;
    uint8_t n_types, n_clusters, n_clients;
    const mt_dm_devtype *types;
    const mt_dm_cluster *const *clusters;  /* server clusters, including the Descriptor */
    const uint32_t *clients;         /* client cluster ids (Descriptor ClientList) */
};

typedef struct {
    const mt_dm_endpoint *eps;       /* eps[0] is endpoint 0 (root); all others are its parts (flat) */
    uint8_t n_eps;
} mt_dm_node;

/* The Descriptor cluster (revision 2, no TagList). List it in every endpoint's `clusters`. */
extern const mt_dm_cluster mt_dm_descriptor;

/* ---- the instance ---- */

typedef struct {
    const mt_dm_node *node;
    mt_im *im;                       /* mark_dirty target; may be NULL (no subscriptions) */
    bool (*access)(void *ctx, const mt_im_subject *s, uint16_t endpoint, uint32_t cluster, uint8_t priv);
    void *access_ctx;                /* ACL check (matter-root/fabric); NULL access denies everything */
    uint32_t dataver_seed;           /* random per boot: cluster instance i starts at seed + i */
} mt_dm_cfg;

struct mt_dm {
    const mt_dm_node *node;
    mt_im *im;
    bool (*access)(void *ctx, const mt_im_subject *s, uint16_t endpoint, uint32_t cluster, uint8_t priv);
    void *access_ctx;
    uint32_t dataver[MT_DM_MAX_CLUSTERS];
};

/* MT_ERR_INVALID if the tables break the rules mt_dm_check lists; the instance is unusable then. */
mt_err mt_dm_init(mt_dm *dm, const mt_dm_cfg *cfg);

/* The matter-im boundary: pass &mt_dm_im with ctx = the mt_dm. */
extern const mt_im_dm mt_dm_im;

/* An attribute's value changed outside a write (sensor, command side effect): bumps the cluster's
 * data version and marks the path dirty. `attr` may be MT_IM_WILD_ID. */
void mt_dm_changed(mt_dm *dm, uint16_t endpoint, uint32_t cluster, uint32_t attr);

/* Current data version of a cluster instance; false if the node has no such cluster. */
bool mt_dm_dataver(const mt_dm *dm, uint16_t endpoint, uint32_t cluster, uint32_t *out);

/* Validates a table set (done by mt_dm_init; separate so the host test can probe each rule):
 *  - eps[0].id == 0, endpoint ids unique, at most MT_DM_MAX_CLUSTERS cluster instances in total;
 *  - every endpoint lists the Descriptor cluster, and no cluster twice;
 *  - no attribute or command id twice in a cluster, no cluster attribute inside 0xFFF8..0xFFFD. */
mt_err mt_dm_check(const mt_dm_node *node);

#endif
