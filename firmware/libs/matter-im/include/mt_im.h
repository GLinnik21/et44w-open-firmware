/* Matter Interaction Model (spec 1.3 ch. 8 and 10.6/10.7): message codec and server engine.
 * Read (wildcards, data-version filters, fabric filtering), chunked ReportData (attribute and
 * list-item granularity), Write (list replace + append, chunked writes), Invoke (one path),
 * Subscribe (priming, min/max intervals, liveness, dirty-path reports, reaping), TimedRequest,
 * StatusResponse, and a tiny fixed event log. Pure C11, no allocation, depends on matter-tlv only.
 *
 * Two boundaries, both injected:
 *  - mt_im_dm: the data model (matter-dm implements it): attribute enumeration, read/write/invoke,
 *    command info, ACL check.
 *  - mt_im_ports: the exchange layer (matter-xchg via matter-node): send on an exchange, open a new
 *    exchange on a session, clock.
 * Sessions and exchanges are opaque 16-bit handles owned by the exchange layer.
 *
 * Exchange contract: every message for protocol 0x0001 goes to mt_im_on_msg. If IM did not call
 * send(..., expect_resp = true) on that exchange while handling it, the exchange layer closes the
 * exchange (after the ack). While IM waits on an exchange and it dies (response timeout, MRP give-up,
 * session gone) the exchange layer calls mt_im_on_exchange_failed; on session close or eviction it
 * calls mt_im_on_session_closed. Both reap what depended on it. */
#ifndef MT_IM_H
#define MT_IM_H

#include <stdbool.h>
#include "mt_tlv.h"

#define MT_IM_PROTOCOL_ID 0x0001u
#define MT_IM_REVISION 11u /* chip v1.3-branch kInteractionModelRevision; peers' values are not checked */

enum { /* IM opcodes */
    MT_IM_OP_STATUS = 0x01, MT_IM_OP_READ = 0x02, MT_IM_OP_SUBSCRIBE = 0x03, MT_IM_OP_SUBSCRIBE_RESP = 0x04,
    MT_IM_OP_REPORT = 0x05, MT_IM_OP_WRITE = 0x06, MT_IM_OP_WRITE_RESP = 0x07, MT_IM_OP_INVOKE = 0x08,
    MT_IM_OP_INVOKE_RESP = 0x09, MT_IM_OP_TIMED = 0x0A
};

/* IM status codes (spec 8.10.1). A handler may also return MT_IM_CST(c): Status FAILURE carrying the
 * cluster-specific status c. */
typedef uint16_t mt_im_status;
#define MT_IM_CST(c) ((mt_im_status)(0x100u | (uint8_t)(c)))
enum {
    MT_IM_SUCCESS = 0x00, MT_IM_FAILURE = 0x01, MT_IM_INVALID_SUBSCRIPTION = 0x7D,
    MT_IM_UNSUPPORTED_ACCESS = 0x7E, MT_IM_UNSUPPORTED_ENDPOINT = 0x7F, MT_IM_INVALID_ACTION = 0x80,
    MT_IM_UNSUPPORTED_COMMAND = 0x81, MT_IM_INVALID_COMMAND = 0x85, MT_IM_UNSUPPORTED_ATTRIBUTE = 0x86,
    MT_IM_CONSTRAINT_ERROR = 0x87, MT_IM_UNSUPPORTED_WRITE = 0x88, MT_IM_RESOURCE_EXHAUSTED = 0x89,
    MT_IM_NOT_FOUND = 0x8B, MT_IM_INVALID_DATA_TYPE = 0x8D, MT_IM_UNSUPPORTED_READ = 0x8F,
    MT_IM_DATA_VERSION_MISMATCH = 0x92, MT_IM_TIMEOUT = 0x94, MT_IM_BUSY = 0x9C,
    MT_IM_UNSUPPORTED_CLUSTER = 0xC3, MT_IM_NEEDS_TIMED_INTERACTION = 0xC6, MT_IM_UNSUPPORTED_EVENT = 0xC7,
    MT_IM_PATHS_EXHAUSTED = 0xC8,
    MT_IM_TIMED_REQUEST_MISMATCH = 0xC9, MT_IM_FAILSAFE_REQUIRED = 0xCA, MT_IM_INVALID_IN_STATE = 0xCB,
    MT_IM_NO_COMMAND_RESPONSE = 0xCC
};
/* Not a status: a command handler returns it to answer later (see mt_im_invoke_done). */
#define MT_IM_DEFER ((mt_im_status)0xFFFFu)

/* Access privileges (spec 6.6.2.1). */
enum { MT_IM_PRIV_VIEW = 1, MT_IM_PRIV_PROXY_VIEW = 2, MT_IM_PRIV_OPERATE = 3, MT_IM_PRIV_MANAGE = 4,
       MT_IM_PRIV_ADMINISTER = 5 };
enum { MT_IM_AUTH_NONE = 0, MT_IM_AUTH_PASE = 1, MT_IM_AUTH_CASE = 2 };

/* ---- sizing (override with -D) ---- */
#ifndef MT_IM_N_SUBS
#define MT_IM_N_SUBS 6          /* subscriptions; >= 3 per fabric is guaranteed by eviction */
#endif
#ifndef MT_IM_N_READS
#define MT_IM_N_READS 2         /* chunked reads in flight (one-chunk reads need no slot) */
#endif
#ifndef MT_IM_SUB_PATHS
#define MT_IM_SUB_PATHS 3       /* attribute + event paths per subscription (spec minimum 3) */
#endif
#ifndef MT_IM_READ_PATHS
#define MT_IM_READ_PATHS 9      /* per Read request (chip's commissioner reads up to 9 at once) */
#endif
#ifndef MT_IM_N_DIRTY
#define MT_IM_N_DIRTY 8         /* global dirty-path set; overflow degrades to full reports */
#endif
#ifndef MT_IM_N_EXCH
#define MT_IM_N_EXCH 2          /* timed windows and chunked writes in flight */
#endif
#ifndef MT_IM_N_DEFER
#define MT_IM_N_DEFER 2         /* invokes answered later */
#endif
#ifndef MT_IM_N_EVENTS
#define MT_IM_N_EVENTS 4        /* event log ring */
#endif
#define MT_IM_EVENT_DATA_MAX 12 /* encoded event fields */
#define MT_IM_MAX_INTERVAL_LIMIT_S 3600 /* SUBSCRIPTION_MAX_INTERVAL_PUBLISHER_LIMIT */
#define MT_IM_MAX_INTERVAL_MIN_S 1       /* smallest MaxInterval we choose (a 0 ceiling is raised to this) */

/* ---- paths ---- */

#define MT_IM_WILD_EP 0xFFFFu
#define MT_IM_WILD_ID 0xFFFFFFFFu   /* cluster, attribute, event or command wildcard */

/* WildcardPathFlags (AttributePathIB tag 6, Matter 1.3). */
enum { MT_IM_WF_SKIP_ROOT = 1u << 0, MT_IM_WF_SKIP_GLOBAL = 1u << 1, MT_IM_WF_SKIP_ATTR_LIST = 1u << 2,
       MT_IM_WF_SKIP_CMD_LISTS = 1u << 4, MT_IM_WF_SKIP_CUSTOM = 1u << 5, MT_IM_WF_SKIP_FIXED = 1u << 6,
       MT_IM_WF_SKIP_OMITTED = 1u << 7, MT_IM_WF_SKIP_DIAG = 1u << 8, MT_IM_PATH_EVENT = 1u << 15 };

typedef struct {
    uint32_t cluster;   /* MT_IM_WILD_ID = any */
    uint32_t id;        /* attribute or event id; MT_IM_WILD_ID = any */
    uint16_t endpoint;  /* MT_IM_WILD_EP = any */
    uint16_t flags;     /* MT_IM_WF_* and MT_IM_PATH_EVENT */
} mt_im_path;

/* ---- the data-model boundary ---- */

enum { /* mt_im_attr.flags */
    MT_IM_ATTR_LIST = 1u << 0,        /* array value: IM chunks it per item */
    MT_IM_ATTR_WRITABLE = 1u << 1,
    MT_IM_ATTR_TIMED_WRITE = 1u << 2,
    MT_IM_ATTR_FIXED = 1u << 3,       /* F quality (WildcardSkipFixedAttributes) */
    MT_IM_ATTR_OMITTED = 1u << 4      /* C quality (WildcardSkipChangesOmittedAttributes) */
};

typedef struct {
    uint16_t endpoint;
    uint32_t cluster, attr;
    uint32_t dataver;       /* the cluster's data version */
    uint8_t flags;          /* MT_IM_ATTR_* */
    uint8_t read_priv, write_priv;
    uint8_t cluster_idx;    /* dense index of (endpoint, cluster) for data-version filters, < 32 */
} mt_im_attr;

/* Who is asking. Filled by the node from the secure session; IM copies it into subscriptions and
 * hands it to the ACL check (which can look up CATs by session). */
typedef struct {
    uint16_t session;
    uint8_t auth;           /* MT_IM_AUTH_* */
    uint8_t fabric;         /* fabric index, 0 = none (PASE before AddNOC) */
    uint64_t node;          /* CASE peer node id; 0 for PASE */
} mt_im_subject;

typedef struct {
    const mt_im_subject *subj;
    bool fabric_filtered;
} mt_im_rctx;

typedef struct {
    const mt_im_subject *subj;
    bool more_chunks;       /* the WriteRequest has MoreChunkedMessages: a list write continues */
    bool timed;             /* the action was preceded by a TimedRequest */
} mt_im_wctx;

typedef enum { MT_IM_WR_VALUE, MT_IM_WR_LIST_APPEND } mt_im_wr_op;

typedef struct {
    uint16_t endpoint;
    uint32_t cluster, command;
} mt_im_cmd;

typedef struct {
    /* Attribute number `idx` of the node in a fixed order (endpoint, cluster, attribute ascending).
     * MT_ERR_NOT_FOUND past the last one. Wildcard expansion and concrete-path errors are derived from
     * this enumeration, so it must list every supported attribute including the global ones. */
    mt_err (*attr_at)(void *ctx, uint16_t idx, mt_im_attr *out);
    /* Encode a value with `tag`. Scalars: item is 0 and the whole value is written. Lists: write item
     * number `item` (counting after fabric filtering), MT_ERR_NOT_FOUND past the last. Return
     * MT_ERR_BUFFER_TOO_SMALL when out of space (IM rolls back). Other errors become FAILURE. */
    mt_err (*read)(void *ctx, const mt_im_rctx *rc, const mt_im_attr *a, uint16_t item, mt_tlv_wr *w,
                   mt_tlv_tag tag);
    /* Write the element under `val` (positioned on it). MT_IM_WR_VALUE replaces the whole value (an
     * array for lists); MT_IM_WR_LIST_APPEND adds one item. The DM bumps the data version and calls
     * mt_im_mark_dirty. */
    mt_im_status (*write)(void *ctx, const mt_im_wctx *wc, const mt_im_attr *a, mt_im_wr_op op,
                          mt_tlv_rd *val);
    /* Command metadata: MT_ERR_NOT_FOUND if the cluster has no such command. */
    mt_err (*cmd_info)(void *ctx, const mt_im_cmd *c, uint8_t *priv, bool *timed);
    /* Run a command. `fields` is positioned on the CommandFields struct (type NONE if absent). To answer
     * with a response command, write its fields into `resp` (already inside the struct), set *resp_cmd
     * and return SUCCESS; leave *resp_cmd as MT_IM_WILD_ID to answer with a status. */
    mt_im_status (*invoke)(void *ctx, const mt_im_subject *s, const mt_im_cmd *c, mt_tlv_rd *fields,
                           mt_tlv_wr *resp, uint32_t *resp_cmd);
    /* Access control: true if `s` holds `priv` on (endpoint, cluster). */
    bool (*access)(void *ctx, const mt_im_subject *s, uint16_t endpoint, uint32_t cluster, uint8_t priv);
} mt_im_dm;

/* ---- the exchange boundary ---- */

#define MT_IM_NEW_EXCH 0xFFFFu

typedef struct {
    /* Send an IM message. *exch == MT_IM_NEW_EXCH opens a new initiator exchange on `session` and
     * stores its handle in *exch. expect_resp keeps the exchange open for the peer's reply. */
    mt_err (*send)(void *ctx, uint16_t session, uint16_t *exch, uint8_t opcode, mt_span payload,
                   bool expect_resp);
    uint32_t (*now_ms)(void *ctx);
    /* Keep `exch` open although IM sends nothing on it now (a deferred invoke). The exchange layer's own idle
     * timeout still ends it (then mt_im_on_exchange_failed). May be NULL: IM then refuses to defer. */
    void (*hold)(void *ctx, uint16_t exch);
} mt_im_ports;

/* ---- engine ---- */

typedef struct {            /* an invoke whose answer is still to come */
    uint16_t exch, session;
    bool used, has_ref;
    uint16_t ref;
    mt_im_cmd cmd;
} mt_im_defer;

/* The last write access check granted in a write interaction: later items of the same list write skip the check
 * (chip WriteHandler ACLCheckCache), so replacing the ACL with [] and appending entries does not lock out the
 * writer half-way. */
typedef struct {
    bool valid;
    uint8_t priv;
    uint16_t endpoint;
    uint32_t cluster, attr;
} mt_im_acl_hit;

typedef struct {
    uint16_t exch, session;
    mt_im_acl_hit acl;      /* chunked write: carried from chunk to chunk */
    uint8_t kind;           /* free / timed window / chunked write */
    bool timed;             /* chunked write: it began as a timed write */
    uint32_t deadline;      /* timed window end */
} mt_im_xstate;

typedef struct {            /* where a (possibly chunked) report resumes */
    uint64_t ev_next;       /* next event number to report */
    uint16_t attr;          /* attr_at index */
    uint16_t item;          /* next list item once in list-item mode */
    uint8_t path;           /* index into the path list */
    uint8_t list_mode;      /* the list's array went out; items follow one per AttributeDataIB */
    uint8_t phase;          /* 0 attributes, 1 events, 2 done */
} mt_im_cursor;

typedef struct {            /* common part of read and subscription state */
    mt_im_subject subj;
    mt_im_cursor cur;
    uint64_t ev_min;        /* from EventFilters */
    uint32_t skip_clusters; /* data-version filters that matched, by cluster_idx */
    uint16_t exch;
    uint8_t n_paths, state;
    bool fabric_filtered, has_report; /* has_report: the current chunk holds an attribute or event */
} mt_im_query;

typedef struct {
    mt_im_query q;
    mt_im_path paths[MT_IM_READ_PATHS];
} mt_im_read;

typedef struct {
    mt_im_query q;
    mt_im_path paths[MT_IM_SUB_PATHS];
    uint32_t id;
    uint32_t last_ms;       /* last report (or SubscribeResponse) sent */
    uint32_t gen_seen;      /* dirty generations already reported */
    uint32_t gen_target;    /* generation the report in flight covers */
    uint16_t min_s, max_s;
    bool dirty, full;       /* dirty: something to report; full: the in-flight report is a full one */
} mt_im_sub;

typedef struct {
    mt_im_path path;        /* concrete or wildcard attribute */
    uint32_t gen;
} mt_im_dirty;

typedef struct {
    uint64_t number;
    uint32_t cluster, id;
    uint32_t sys_ms;
    uint16_t endpoint;
    uint8_t priority, len;
    uint8_t data[MT_IM_EVENT_DATA_MAX];
} mt_im_event;

typedef struct {
    const mt_im_dm *dm; void *dm_ctx;
    const mt_im_ports *port; void *port_ctx;
    mt_buf tx;              /* IM payload buffer; its capacity is the chunk size */
    mt_im_read reads[MT_IM_N_READS];
    mt_im_sub subs[MT_IM_N_SUBS];
    mt_im_xstate xs[MT_IM_N_EXCH];
    mt_im_defer defer[MT_IM_N_DEFER];
    uint16_t cur_exch;      /* exchange of the invoke being handled (mt_im_invoke_exch) */
    mt_im_dirty dirty[MT_IM_N_DIRTY];
    uint32_t gen, full_gen;  /* dirty generation counter; subs older than full_gen report everything */
    uint32_t next_sub_id;
    mt_im_event events[MT_IM_N_EVENTS];
    uint64_t next_event;
} mt_im;

typedef struct {
    const mt_im_dm *dm; void *dm_ctx;
    const mt_im_ports *port; void *port_ctx;
    mt_buf tx;              /* >= 128 bytes; ~1150 on the device (IPv6 MTU minus headers and MIC) */
    uint32_t sub_id_seed;   /* random: subscription ids continue from here */
    uint64_t event_base;    /* first event number of this boot (persisted epoch) */
} mt_im_cfg;

void mt_im_init(mt_im *im, const mt_im_cfg *cfg);

/* An IM message arrived on `exch` (new or one IM waits on). `s` describes its session; a subject whose auth
 * is not PASE or CASE is ignored (no reply). */
void mt_im_on_msg(mt_im *im, const mt_im_subject *s, uint16_t exch, uint8_t opcode, mt_span payload);
/* The exchange IM was waiting on died (MRP gave up, response timeout): reaps a subscription whose
 * report was in flight, drops a chunked read/write or timed window. matter-node also calls it when it
 * closes an exchange IM left without a pending reply (e.g. IM's send failed), so it must stay a no-op for
 * an exchange IM has finished with (finished queries hold no handle or are not in Q_WAIT/Q_REPORT). */
void mt_im_on_exchange_failed(mt_im *im, uint16_t exch);
/* The session was closed or evicted: its subscriptions and exchanges are dropped. */
void mt_im_on_session_closed(mt_im *im, uint16_t session);
/* A fabric was removed: its subscriptions are dropped. */
void mt_im_on_fabric_removed(mt_im *im, uint8_t fabric);

/* While a command handler runs: the exchange of the invoke it serves (with the subject's session, the key of
 * mt_im_invoke_done). Handlers reach `im` through mt_dm.im. */
static inline uint16_t mt_im_invoke_exch(const mt_im *im) { return im->cur_exch; }

/* Answer an invoke whose handler returned MT_IM_DEFER (it saved s->session and mt_im_invoke_exch). The command
 * path and CommandRef come from the request. st != SUCCESS, or resp_cmd == MT_IM_WILD_ID, sends a status;
 * otherwise `fields` are the response's members, already TLV-encoded with context tags (no struct wrapper).
 * MT_ERR_NOT_FOUND if the invoke is gone (exchange died, session closed, client sent something else on it):
 * drop the result. A suppressed response (SuppressResponse in the request) is sent anyway. If the node has no
 * `hold` port, or all MT_IM_N_DEFER slots are taken, the handler's MT_IM_DEFER becomes FAILURE/BUSY at once and
 * a later call finds nothing. Other errors: the message could not be sent (the exchange then times out). */
mt_err mt_im_invoke_done(mt_im *im, uint16_t session, uint16_t exch, mt_im_status st, uint32_t resp_cmd,
                         mt_span fields);

/* For command handlers: field `tag` of the CommandFields struct `fields` (positioned on it, left unchanged).
 * MT_OK with *out on the first such field, MT_ERR_NOT_FOUND if absent, MT_ERR_INVALID if `fields` is not a
 * struct. */
mt_err mt_im_field(const mt_tlv_rd *fields, uint8_t tag, mt_tlv_rd *out);

/* Runs due subscription reports; returns ms until it next needs to run (UINT32_MAX = idle). */
uint32_t mt_im_poll(mt_im *im);

/* An attribute changed (wildcards allowed). Subscriptions covering it report after their min interval. */
void mt_im_mark_dirty(mt_im *im, uint16_t endpoint, uint32_t cluster, uint32_t attr);

/* Log an event (e.g. Basic Information StartUp: endpoint 0, cluster 0x28, id 0, priority 2 (CRITICAL),
 * fields = encoded {0: SoftwareVersion}). `fields` are the struct members with context tags, at most
 * MT_IM_EVENT_DATA_MAX bytes. The oldest entry is overwritten. Returns the event number via *number. */
mt_err mt_im_event_emit(mt_im *im, uint16_t endpoint, uint32_t cluster, uint32_t id, uint8_t priority,
                        mt_span fields, uint64_t *number);

/* Number of live subscriptions (diagnostics/tests). */
unsigned mt_im_sub_count(const mt_im *im);
/* Live subscriptions on one session (the node pushes this to the exchange layer's eviction policy). */
unsigned mt_im_sub_count_session(const mt_im *im, uint16_t session);

#endif
