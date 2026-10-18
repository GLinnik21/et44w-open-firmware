/* Matter fabric table. Pure C11, no allocation; the caller owns the table object (~3.3 KiB, see
 * mt_fabric_table) and passes scratch buffers of MT_FABRIC_SCRATCH bytes to the operations that
 * verify certificates or touch storage.
 *
 * Model
 *  - Up to MT_FABRIC_MAX committed fabrics, each with an index 1..254. Committed fabrics keep only
 *    their small identity in RAM (ids, root public key, IPK, label, ACL); RCAC/ICAC/NOC and the
 *    operational private key stay in storage and are read on demand.
 *  - One RAM-staged pending fabric (from AddNOC) or pending credential update (from UpdateNOC) lives
 *    while the fail-safe is armed. mt_fabric_nth()/mt_fabric_get() include it (a pending update
 *    replaces the committed entry of the same index), so CASE and the IM see it before commit.
 *    mt_fabric_commit() persists it, mt_fabric_abort() discards it.
 *  - Fabric indices are handed out round-robin from the last one used (not reused right away). The
 *    cursor is RAM only, so after a reboot the lowest free index is used again.
 *
 * Storage contract (mt_kv_ops): every record belongs to a fabric image. Every persisting call writes
 * the five records of one fabric (RCAC, ICAC, NOC, META, ACL; an absent ICAC is a del) and then calls
 * finish(apply). `get` always returns the last *applied* state, never staged writes. The port stages
 * set/del in the spare module and makes them durable and visible atomically in finish(apply = true)
 * (index flip); finish(apply = false) drops them. */
#ifndef MT_FABRIC_H
#define MT_FABRIC_H

#include <stdbool.h>
#include "mt_cert.h"
#include "mt_core.h"
#include "mt_crypto.h"
#include "mt_tlv.h"

#define MT_FABRIC_MAX 3
#define MT_FABRIC_INDEX_MAX 254
#define MT_FABRIC_CERT_MAX 400          /* largest stored TLV certificate (spec kMaxCHIPCertLength) */
#define MT_FABRIC_LABEL_MAX 32
#define MT_FABRIC_SCRATCH MT_CERT_SCRATCH
#define MT_CFID_LEN 8                   /* compressed fabric ID */
#define MT_IPK_LEN 16
#define MT_DEST_ID_LEN MT_SHA256_LEN
#define MT_CASE_RANDOM_LEN 32

/* ACL caps are the spec minimums (4 entries per fabric, 4 subjects, 3 targets). */
#ifndef MT_ACL_MAX_ENTRIES
#define MT_ACL_MAX_ENTRIES 4
#endif
#ifndef MT_ACL_MAX_SUBJECTS
#define MT_ACL_MAX_SUBJECTS 4
#endif
#ifndef MT_ACL_MAX_TARGETS
#define MT_ACL_MAX_TARGETS 3
#endif

/* ---- key/value port interface ---- */

/* Key = fabric index << 8 | record kind. Index 0 is reserved for non-fabric records of the node. */
enum { MT_FKIND_RCAC = 1, MT_FKIND_ICAC, MT_FKIND_NOC, MT_FKIND_META, MT_FKIND_ACL };
#define MT_FKEY(index, kind) ((uint16_t)(((unsigned)(index) << 8) | (unsigned)(kind)))

/* mt_kv_ops (the storage port) is defined in mt_core.h. */

/* ---- access control entries (shape of the Access Control cluster's entry struct) ---- */

enum { MT_ACL_PRIV_VIEW = 1, MT_ACL_PRIV_PROXY_VIEW, MT_ACL_PRIV_OPERATE, MT_ACL_PRIV_MANAGE, MT_ACL_PRIV_ADMINISTER };
enum { MT_ACL_AUTH_PASE = 1, MT_ACL_AUTH_CASE, MT_ACL_AUTH_GROUP };
#define MT_ACL_NO_CLUSTER 0xFFFFFFFFu   /* null target fields */
#define MT_ACL_NO_ENDPOINT 0xFFFFu
#define MT_ACL_NO_DEVTYPE 0xFFFFFFFFu

typedef struct { uint32_t cluster; uint16_t endpoint; uint32_t devtype; } mt_acl_target;
typedef struct {
    uint8_t privilege, auth_mode, n_subjects, n_targets;   /* 0 subjects / 0 targets = null (any) */
    uint64_t subjects[MT_ACL_MAX_SUBJECTS];
    mt_acl_target targets[MT_ACL_MAX_TARGETS];
} mt_acl_entry;

/* Spec constraints on a written entry: privilege 1..5, auth mode CASE or Group (PASE entries are not
 * allowed), Group never Administer, subjects valid for the auth mode (node ID or CAT for CASE), targets
 * non-empty and not endpoint+device type together. */
bool mt_acl_entry_valid(const mt_acl_entry *e);
/* IM encoding: struct { 1 privilege, 2 authMode, 3 subjects (array|null), 4 targets (array|null) } with
 * target { 0 cluster, 1 endpoint, 2 deviceType } (null fields omitted as null). The fabric index tag
 * (254) is written by the cluster layer, not here. Decode ignores tag 254 and unknown tags;
 * MT_ERR_BUFFER_TOO_SMALL when a list exceeds the caps, MT_ERR_INVALID for anything else wrong
 * (validity of the values is mt_acl_entry_valid()). `r` is positioned on the struct element. */
mt_err mt_acl_entry_encode(mt_tlv_wr *w, mt_tlv_tag tag, const mt_acl_entry *e);
/* The same fields (1..4) into a struct the caller has opened, so it can add the fabric index. */
mt_err mt_acl_entry_encode_fields(mt_tlv_wr *w, const mt_acl_entry *e);
mt_err mt_acl_entry_decode(mt_tlv_rd *r, mt_acl_entry *e);

/* ---- identifiers (spec 4.3.2.2, 4.13.2.4, 4.14.2.4) ---- */

/* Compressed fabric ID = HKDF-SHA256(ikm = root public key without the 0x04 prefix, salt = fabric ID
 * big endian, info = "CompressedFabric", L = 8). */
mt_err mt_fabric_compress_id(const uint8_t root_pub[MT_P256_POINT_LEN], uint64_t fabric_id, uint8_t out[MT_CFID_LEN]);
/* Operational IPK = HKDF-SHA256(ikm = epoch key, salt = compressed fabric ID, info = "GroupKey v1.0", L = 16). */
mt_err mt_fabric_derive_ipk(const uint8_t epoch[MT_IPK_LEN], const uint8_t cfid[MT_CFID_LEN], uint8_t out[MT_IPK_LEN]);
/* CASE destination ID = HMAC-SHA256(IPK, initiatorRandom || rootPubKey || fabricId LE || nodeId LE). */
mt_err mt_fabric_destination_id(const uint8_t ipk[MT_IPK_LEN], const uint8_t random[MT_CASE_RANDOM_LEN],
                                const uint8_t root_pub[MT_P256_POINT_LEN], uint64_t fabric_id, uint64_t node_id,
                                uint8_t out[MT_DEST_ID_LEN]);

/* ---- fabric and table ---- */

typedef struct {
    uint8_t index;                      /* 0 = unused slot */
    bool pending;                       /* this is the staged fabric / staged update, not yet committed */
    uint16_t vendor_id;                 /* of the administrator that added it */
    uint64_t fabric_id, node_id;
    uint8_t cfid[MT_CFID_LEN];
    uint8_t root_pub[MT_P256_POINT_LEN];
    uint8_t ipk_epoch[MT_IPK_LEN];
    uint8_t ipk[MT_IPK_LEN];            /* operational key, what CASE uses */
    char label[MT_FABRIC_LABEL_MAX + 1];
    uint8_t n_acl;
    mt_acl_entry acl[MT_ACL_MAX_ENTRIES];
} mt_fabric;

enum { MT_FABRIC_PEND_NONE = 0, MT_FABRIC_PEND_NEW, MT_FABRIC_PEND_UPDATE };

typedef struct {
    const mt_kv_ops *kv;
    mt_fabric slots[MT_FABRIC_MAX];
    uint8_t next_index;                 /* allocation cursor */
    uint8_t skipped;                    /* stored fabrics mt_fabric_load() could not use */
    struct {
        uint8_t kind;                   /* MT_FABRIC_PEND_* */
        bool has_key;
        mt_fabric fab;                  /* valid for NEW / UPDATE */
        uint8_t priv[MT_P256_SCALAR_LEN], pub[MT_P256_POINT_LEN];  /* staged operational key pair */
        uint16_t rcac_len, icac_len, noc_len;
        uint8_t rcac[MT_FABRIC_CERT_MAX], icac[MT_FABRIC_CERT_MAX], noc[MT_FABRIC_CERT_MAX];
    } pend;
} mt_fabric_table;

void mt_fabric_init(mt_fabric_table *t, const mt_kv_ops *kv);
/* Read all stored fabrics (indices 1..254) into RAM. Unreadable or inconsistent images are skipped and
 * counted in t->skipped; more images than slots: the extra ones are skipped too. MT_OK otherwise. */
mt_err mt_fabric_load(mt_fabric_table *t, mt_buf scratch);

/* Lookups include the pending fabric. nth(0..count-1) walks committed fabrics in slot order (a pending
 * update stands in for its committed entry), then a pending new fabric. */
unsigned mt_fabric_count(const mt_fabric_table *t);
const mt_fabric *mt_fabric_nth(const mt_fabric_table *t, unsigned n);
const mt_fabric *mt_fabric_get(const mt_fabric_table *t, uint8_t index);
unsigned mt_fabric_committed_count(const mt_fabric_table *t);
int mt_fabric_pending_kind(const mt_fabric_table *t);          /* MT_FABRIC_PEND_* */
const mt_fabric *mt_fabric_pending(const mt_fabric_table *t);  /* NULL when none */

/* CASE: find the fabric (committed or pending) whose destination ID for its own node equals dest_id.
 * MT_ERR_NOT_FOUND when none matches. */
mt_err mt_fabric_match_destination(const mt_fabric_table *t, const uint8_t random[MT_CASE_RANDOM_LEN],
                                   const uint8_t dest_id[MT_DEST_ID_LEN], const mt_fabric **out);

/* Credentials of a fabric returned by the lookups. A committed fabric's certificate is read into `out`
 * (>= MT_FABRIC_CERT_MAX); a pending one points into the table. MT_ERR_NOT_FOUND for an absent ICAC. */
mt_err mt_fabric_read_cert(const mt_fabric_table *t, const mt_fabric *f, int kind /* MT_FKIND_RCAC|ICAC|NOC */,
                           mt_buf out, mt_span *tlv);
mt_err mt_fabric_read_opkey(const mt_fabric_table *t, const mt_fabric *f, uint8_t priv[MT_P256_SCALAR_LEN]);

/* ---- commissioning (Operational Credentials flow) ---- */

/* CSRRequest: remember the freshly generated operational key pair for the pending NOC. State error once
 * AddNOC / UpdateNOC has run. */
mt_err mt_fabric_stage_key(mt_fabric_table *t, const uint8_t priv[MT_P256_SCALAR_LEN], const uint8_t pub[MT_P256_POINT_LEN]);
/* AddTrustedRootCertificate: stage the RCAC (decoded and checked as a root CA; once per fail-safe). */
mt_err mt_fabric_stage_rcac(mt_fabric_table *t, mt_span rcac);
/* AddNOC: verify NOC[/ICAC]/staged RCAC (validity checked when now != 0, Matter epoch seconds), require the
 * NOC key to be the staged key, and stage a new fabric with an Administer/CASE ACL entry for
 * admin_subject. icac.len = 0 for none. On success *index is the new fabric index.
 * Errors: MT_ERR_STATE (no staged key or root, or already pending), MT_ERR_BUFFER_TOO_SMALL (table full),
 * MT_ERR_INVALID (bad certs, key mismatch, same root key and fabric ID as an existing fabric),
 * MT_ERR_EXPIRED, MT_ERR_CRYPTO (signature). mt_fabric_conflict() lets the caller tell the conflict apart. */
mt_err mt_fabric_add_noc(mt_fabric_table *t, mt_span noc, mt_span icac, const uint8_t ipk_epoch[MT_IPK_LEN],
                         uint64_t admin_subject, uint16_t admin_vendor, uint32_t now, mt_buf scratch,
                         uint8_t *index);
/* Does a committed or pending fabric with this root key and fabric ID exist? */
bool mt_fabric_conflict(const mt_fabric_table *t, const uint8_t root_pub[MT_P256_POINT_LEN], uint64_t fabric_id);
/* UpdateNOC: stage new NOC[/ICAC] (same root key and fabric ID, the staged key) for committed fabric
 * `index`. Errors as AddNOC; MT_ERR_NOT_FOUND for an unknown index. */
mt_err mt_fabric_update_noc(mt_fabric_table *t, uint8_t index, mt_span noc, mt_span icac, uint32_t now, mt_buf scratch);
/* NOCResponse classification after a failed AddNOC/UpdateNOC: verify only the chain NOC[/ICAC] -> RCAC (no key or
 * conflict check, validity skipped) against the staged RCAC (index 0) or committed fabric `index`'s RCAC, which is
 * read into the table's free staging buffer. MT_ERR_STATE while something is pending (index != 0); otherwise the
 * mt_cert_decode / mt_cert_verify_chain result. */
mt_err mt_fabric_check_chain(mt_fabric_table *t, uint8_t index, mt_span noc, mt_span icac, mt_buf scratch);
/* CommissioningComplete / UpdateNOC commit: persist the pending fabric. On a storage error the pending state
 * is kept so the caller can retry or abort. MT_ERR_STATE when nothing is pending. */
mt_err mt_fabric_commit(mt_fabric_table *t, mt_buf scratch);
/* Fail-safe expiry: drop the pending fabric/update and any staged key or root; wipes the staged key. */
void mt_fabric_abort(mt_fabric_table *t);

/* ---- changes to existing fabrics (persisted at once when committed) ---- */

/* RemoveFabric (also drops the pending fabric of that index). MT_ERR_NOT_FOUND for an unknown index. */
mt_err mt_fabric_remove(mt_fabric_table *t, uint8_t index);
/* Replace a fabric's ACL. MT_ERR_INVALID when an entry is invalid, MT_ERR_BUFFER_TOO_SMALL above the cap. */
mt_err mt_fabric_acl_set(mt_fabric_table *t, uint8_t index, const mt_acl_entry *e, unsigned n, mt_buf scratch);
/* UpdateFabricLabel: mt_fabric_set_label gives MT_ERR_INVALID when longer than MT_FABRIC_LABEL_MAX or used by any
 * other fabric (committed or pending; same root or not), mt_fabric_label_in_use says which; the empty label is never
 * in use. The root cluster answers a conflict with NOCResponse LabelConflict (10), see operational_credentials.c. */
bool mt_fabric_label_in_use(const mt_fabric_table *t, const char *label, size_t len, uint8_t except_index);
mt_err mt_fabric_set_label(mt_fabric_table *t, uint8_t index, const char *label, size_t len, mt_buf scratch);

#endif
