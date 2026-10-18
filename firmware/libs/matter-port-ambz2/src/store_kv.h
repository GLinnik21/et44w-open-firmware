/* store_kv: the mt_kv_ops contract (mt_core.h) on six small key/value modules. Pure C11, no SDK:
 * the module store is injected (store_dct.c on the device, a RAM fake in the host test).
 *
 * Modules: MTP_MOD_BOOT (BOOT record, safe-mode counter), MTP_MOD_NODE (index, WIFI, node-level records) and
 * MTP_MOD_F0 .. +3 (fabric images). Variable names are at most MTP_NAME_MAX characters: "kXX" (XX = record kind
 * in hex) for mt_kv keys, upper-case words ("IDX", "WIFI", "SAFE") for the port's own records.
 *
 * Keys (MT_FKEY: fabric index << 8 | kind):
 *  - index 0 (node-level: BASIC, REGULATORY, BOOT): one variable each, in MTP_MOD_BOOT (MT_NODE_KEY_BOOT) or
 *    MTP_MOD_NODE. A finish(apply) writes them at once, or, while busy() says a handshake / BLE link is running,
 *    keeps them in RAM (get sees them) until mtp_kv_flush (a flash write stalls
 *    the BLE radio's timing).
 *  - index 1..254 (fabric records, kinds 1..MTP_FKIND_MAX): every fabric lives in one of the four fabric modules;
 *    the "IDX" variable maps fabric index -> module. A batch (the set/del calls up to finish) may touch one fabric
 *    only, and no node-level keys. Its writes go straight into a free ("scratch") module, emptied first; kinds the
 *    batch did not touch are copied over from the fabric's current module at finish. finish(apply) then rewrites
 *    IDX: that single variable write is the commit (a cut before it leaves the old image, after it the new one).
 *    A batch that leaves the fabric with no records drops it from IDX. After the IDX write the module the fabric
 *    left is erased (reset), so a removed or replaced operational key does not stay in flash; finish(false)
 *    erases the scratch it wrote to. mtp_kv_init erases free modules that still hold records (a power cut
 *    between the IDX write and that erase).
 *    Fabric batches always run synchronously: they come from CommissioningComplete (BLE is down by then),
 *    UpdateNOC, ACL / label writes and RemoveFabric, never from inside a PASE/CASE handshake.
 * At most MTP_FMODS - 1 fabrics: one module is always free as the scratch.
 * Not thread-safe: one task (the Matter task) owns it. */
#ifndef MTP_STORE_KV_H
#define MTP_STORE_KV_H

#include "mt_core.h"

enum { MTP_MOD_BOOT = 0, MTP_MOD_NODE = 1, MTP_MOD_F0 = 2 };
#define MTP_FMODS 4
#define MTP_N_MODS (MTP_MOD_F0 + MTP_FMODS)
#define MTP_NAME_MAX 4            /* DCT variable_name_size: strlen of a name */
#define MTP_VALUE_SIZE 512        /* DCT variable_value_size */
#define MTP_VALUE_MAX (MTP_VALUE_SIZE - 4) /* dct_set_variable_new2 rejects len > value_size - 4 */
#define MTP_FKIND_MAX 7           /* fabric record kinds 1..7 (matter-fabric uses 1..5) */
#define MTP_SMALL_MAX 96          /* node-level record (BASIC ~45 B, REGULATORY, BOOT ~20 B) */
#define MTP_SMALL_STAGE 3         /* node-level keys per batch */
#define MTP_DEFER_MAX 3           /* node-level records waiting for an idle moment */

#define MTP_NAME_INDEX "IDX"
#define MTP_NAME_WIFI "WIFI"
#define MTP_NAME_SAFE "SAFE"

/* The injected module store. get: MT_ERR_NOT_FOUND / MT_ERR_BUFFER_TOO_SMALL / MT_ERR_IO; del of an absent
 * variable is MT_OK; reset empties the module. */
typedef struct {
    void *ctx;
    mt_err (*get)(void *ctx, unsigned mod, const char *name, mt_buf out, size_t *len);
    mt_err (*set)(void *ctx, unsigned mod, const char *name, mt_span val);
    mt_err (*del)(void *ctx, unsigned mod, const char *name);
    mt_err (*reset)(void *ctx, unsigned mod);
} mtp_mods;

typedef struct {
    uint16_t key;
    bool del;
    uint8_t len;
    uint8_t val[MTP_SMALL_MAX];
} mtp_small;

typedef struct {
    uint8_t n;
    struct { uint8_t fidx, mod; } e[MTP_FMODS];   /* mod 0..MTP_FMODS-1 (module MTP_MOD_F0 + mod) */
} mtp_fmap;

typedef struct mtp_kv {
    mtp_mods m;
    bool (*busy)(void *ctx);
    void *busy_ctx;
    uint8_t *tmp;                 /* MTP_VALUE_MAX bytes, for copying records at finish */
    mtp_fmap map;                 /* applied fabric index -> module */
    struct {                      /* the batch in progress */
        uint8_t fidx;             /* 0 = no fabric records staged */
        uint8_t mod;              /* its scratch module (0..MTP_FMODS-1), valid when fidx != 0 */
        bool emptied;             /* the scratch has been reset in this batch */
        bool bad;                 /* a write failed: finish(apply) fails */
        uint8_t staged;           /* kinds set or deleted (bit = kind) */
        uint8_t written;          /* kinds present in the scratch */
        uint8_t n_small;
        mtp_small small[MTP_SMALL_STAGE];
    } b;
    uint8_t n_defer;
    mtp_small defer[MTP_DEFER_MAX];
    mt_kv_ops ops;                /* ctx = this */
} mtp_kv;

/* Loads IDX. MT_ERR_INVALID if it is unreadable (the store then starts with no fabrics), MT_ERR_IO if the module
 * store failed; the object is usable in every case. tmp: MTP_VALUE_MAX bytes, must outlive k. */
mt_err mtp_kv_init(mtp_kv *k, const mtp_mods *m, uint8_t *tmp);
static inline const mt_kv_ops *mtp_kv_ops_of(mtp_kv *k) { return &k->ops; }
/* busy(ctx) true = defer node-level writes (NULL = never busy). */
void mtp_kv_set_busy(mtp_kv *k, bool (*busy)(void *ctx), void *ctx);
/* Node-level records waiting to be written. */
bool mtp_kv_deferred(const mtp_kv *k);
/* Writes them now (call when idle). MT_ERR_IO if one failed (it stays queued). */
mt_err mtp_kv_flush(mtp_kv *k);
/* Fabric indices in the store (diagnostics). */
unsigned mtp_kv_fabrics(const mtp_kv *k);

/* Pure helpers, exposed for the tests. */
void mtp_kv_name(uint16_t key, char out[MTP_NAME_MAX + 1]);          /* "kXX" of the key's kind */
unsigned mtp_kv_small_module(uint16_t key);                            /* module of a node-level key */
size_t mtp_fmap_encode(const mtp_fmap *m, uint8_t *out, size_t cap);   /* 0 if it does not fit */
mt_err mtp_fmap_decode(mtp_fmap *m, const uint8_t *in, size_t len);    /* MT_ERR_INVALID if inconsistent */

#endif
