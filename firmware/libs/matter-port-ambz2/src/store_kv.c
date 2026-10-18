/* mt_kv_ops over the module store, see store_kv.h. */
#include <string.h>

#include "store_kv.h"

#define KEY_BOOT 0x0023u          /* MT_NODE_KEY_BOOT (checked against mt_node.h in kv.c) */
#define FMAP_VERSION 1
#define FMAP_MAX_BYTES (2 + 2 * MTP_FMODS)

static uint8_t fidx_of(uint16_t key) { return (uint8_t)(key >> 8); }
static uint8_t kind_of(uint16_t key) { return (uint8_t)key; }

void mtp_kv_name(uint16_t key, char out[MTP_NAME_MAX + 1])
{
    static const char hex[] = "0123456789ABCDEF";
    out[0] = 'k';
    out[1] = hex[kind_of(key) >> 4];
    out[2] = hex[kind_of(key) & 15];
    out[3] = 0;
}

unsigned mtp_kv_small_module(uint16_t key) { return key == KEY_BOOT ? MTP_MOD_BOOT : MTP_MOD_NODE; }

/* ---- fabric map (IDX): [version][n]{[fabric index][module]}*n ---- */

size_t mtp_fmap_encode(const mtp_fmap *m, uint8_t *out, size_t cap)
{
    size_t len = 2u + 2u * m->n;
    if (m->n > MTP_FMODS || cap < len) return 0;
    out[0] = FMAP_VERSION;
    out[1] = m->n;
    for (unsigned i = 0; i < m->n; i++) {
        out[2 + 2 * i] = m->e[i].fidx;
        out[3 + 2 * i] = m->e[i].mod;
    }
    return len;
}

mt_err mtp_fmap_decode(mtp_fmap *m, const uint8_t *in, size_t len)
{
    unsigned used = 0;
    memset(m, 0, sizeof *m);
    if (len < 2 || in[0] != FMAP_VERSION || in[1] > MTP_FMODS - 1 || len != 2u + 2u * in[1]) return MT_ERR_INVALID;
    for (unsigned i = 0; i < in[1]; i++) {
        uint8_t f = in[2 + 2 * i], mod = in[3 + 2 * i];
        if (f == 0 || f == 0xFF || mod >= MTP_FMODS || (used & (1u << mod))) goto bad;
        for (unsigned j = 0; j < i; j++) if (m->e[j].fidx == f) goto bad;
        used |= 1u << mod;
        m->e[i].fidx = f;
        m->e[i].mod = mod;
    }
    m->n = in[1];
    return MT_OK;
bad:
    memset(m, 0, sizeof *m);
    return MT_ERR_INVALID;
}

static int fmap_find(const mtp_fmap *m, uint8_t fidx)
{
    for (unsigned i = 0; i < m->n; i++) if (m->e[i].fidx == fidx) return (int)i;
    return -1;
}

/* First module no fabric uses; -1 if none. */
static int fmap_free_mod(const mtp_fmap *m)
{
    unsigned used = 0;
    for (unsigned i = 0; i < m->n; i++) used |= 1u << m->e[i].mod;
    for (int mod = 0; mod < MTP_FMODS; mod++) if (!(used & (1u << mod))) return mod;
    return -1;
}

static mt_err fmap_store(mtp_kv *k, const mtp_fmap *m)
{
    uint8_t buf[FMAP_MAX_BYTES];
    size_t len = mtp_fmap_encode(m, buf, sizeof buf);
    if (!len) return MT_ERR_INVALID;
    return k->m.set(k->m.ctx, MTP_MOD_NODE, MTP_NAME_INDEX, mt_span_of(buf, len)) ? MT_ERR_IO : MT_OK;
}

/* ---- node-level records ---- */

static mtp_small *small_find(mtp_small *list, uint8_t n, uint16_t key)
{
    for (unsigned i = 0; i < n; i++) if (list[i].key == key) return &list[i];
    return NULL;
}

static mt_err small_write(mtp_kv *k, const mtp_small *s)
{
    char name[MTP_NAME_MAX + 1];
    unsigned mod = mtp_kv_small_module(s->key);
    mtp_kv_name(s->key, name);
    return (s->del ? k->m.del(k->m.ctx, mod, name) : k->m.set(k->m.ctx, mod, name, mt_span_of(s->val, s->len)))
               ? MT_ERR_IO : MT_OK;
}

static void defer_drop(mtp_kv *k, uint16_t key)
{
    mtp_small *d = small_find(k->defer, k->n_defer, key);
    if (!d) return;
    *d = k->defer[--k->n_defer];
}

/* Applies one staged node-level record: written now, or queued while busy (queue full: written anyway). */
static mt_err small_apply(mtp_kv *k, const mtp_small *s)
{
    if (k->busy && k->busy(k->busy_ctx)) {
        mtp_small *d = small_find(k->defer, k->n_defer, s->key);
        if (!d && k->n_defer < MTP_DEFER_MAX) d = &k->defer[k->n_defer++];
        if (d) { *d = *s; return MT_OK; }
    }
    mt_err e = small_write(k, s);
    if (!e) defer_drop(k, s->key);
    return e;
}

static mt_err stage_small(mtp_kv *k, uint16_t key, bool del, mt_span val)
{
    mtp_small *s;
    if (k->b.fidx) return MT_ERR_INVALID;                     /* mixed batch */
    if (val.len > MTP_SMALL_MAX) return MT_ERR_BUFFER_TOO_SMALL;
    s = small_find(k->b.small, k->b.n_small, key);
    if (!s) {
        if (k->b.n_small >= MTP_SMALL_STAGE) return MT_ERR_IO;
        s = &k->b.small[k->b.n_small++];
    }
    s->key = key;
    s->del = del;
    s->len = (uint8_t)val.len;
    if (val.len) memcpy(s->val, val.p, val.len);
    return MT_OK;
}

/* ---- fabric records ---- */

/* Opens (or joins) the batch of fabric `fidx`: picks the scratch module. */
static mt_err batch_join(mtp_kv *k, uint8_t fidx)
{
    int mod;
    if (k->b.n_small) return MT_ERR_INVALID;                  /* mixed batch */
    if (k->b.fidx) return k->b.fidx == fidx ? MT_OK : MT_ERR_INVALID;
    /* a new fabric must leave a module free for the next update */
    if (fmap_find(&k->map, fidx) < 0 && k->map.n >= MTP_FMODS - 1) return MT_ERR_BUFFER_TOO_SMALL;
    mod = fmap_free_mod(&k->map);
    if (mod < 0) return MT_ERR_BUFFER_TOO_SMALL;
    k->b.fidx = fidx;
    k->b.mod = (uint8_t)mod;
    return MT_OK;
}

static mt_err scratch_ready(mtp_kv *k)
{
    if (k->b.emptied) return MT_OK;
    if (k->m.reset(k->m.ctx, MTP_MOD_F0 + k->b.mod)) return MT_ERR_IO;
    k->b.emptied = true;
    return MT_OK;
}

static mt_err fab_set(mtp_kv *k, uint16_t key, mt_span val)
{
    char name[MTP_NAME_MAX + 1];
    uint8_t kind = kind_of(key);
    mt_err e;
    if (kind < 1 || kind > MTP_FKIND_MAX) return MT_ERR_INVALID;
    if (val.len > MTP_VALUE_MAX) return MT_ERR_BUFFER_TOO_SMALL;
    if ((e = batch_join(k, fidx_of(key)))) return e;
    if ((e = scratch_ready(k))) { k->b.bad = true; return e; }
    mtp_kv_name(key, name);
    if (k->m.set(k->m.ctx, MTP_MOD_F0 + k->b.mod, name, val)) { k->b.bad = true; return MT_ERR_IO; }
    k->b.staged |= (uint8_t)(1u << kind);
    k->b.written |= (uint8_t)(1u << kind);
    return MT_OK;
}

static mt_err fab_del(mtp_kv *k, uint16_t key)
{
    char name[MTP_NAME_MAX + 1];
    uint8_t kind = kind_of(key), fidx = fidx_of(key);
    mt_err e;
    bool stored = fmap_find(&k->map, fidx) >= 0;
    /* Deleting what can't exist is a no-op, also outside the batch's fabric (the contract allows absent deletes). */
    if (kind < 1 || kind > MTP_FKIND_MAX || (!stored && k->b.fidx != fidx)) return MT_OK;
    if ((e = batch_join(k, fidx))) return e;
    if (k->b.written & (1u << kind)) {
        mtp_kv_name(key, name);
        if (k->m.del(k->m.ctx, MTP_MOD_F0 + k->b.mod, name)) { k->b.bad = true; return MT_ERR_IO; }
    }
    k->b.staged |= (uint8_t)(1u << kind);
    k->b.written &= (uint8_t)~(1u << kind);
    return MT_OK;
}

/* finish(apply) of a fabric batch: completes the scratch image, then the IDX flip. */
static mt_err fab_commit(mtp_kv *k)
{
    mtp_fmap next = k->map;
    int cur = fmap_find(&k->map, k->b.fidx);
    unsigned cur_mod = cur >= 0 ? MTP_MOD_F0 + k->map.e[cur].mod : 0;
    uint8_t copy = 0;
    mt_err e;

    if (cur >= 0) {                                           /* kinds the batch left alone stay as they are */
        for (unsigned kind = 1; kind <= MTP_FKIND_MAX; kind++) {
            char name[MTP_NAME_MAX + 1];
            size_t len;
            if (k->b.staged & (1u << kind)) continue;
            mtp_kv_name((uint16_t)kind, name);
            e = k->m.get(k->m.ctx, cur_mod, name, mt_buf_of(k->tmp, MTP_VALUE_MAX), &len);
            if (e == MT_ERR_NOT_FOUND) continue;
            if (e) return MT_ERR_IO;
            if (!copy && scratch_ready(k)) return MT_ERR_IO;
            if (k->m.set(k->m.ctx, MTP_MOD_F0 + k->b.mod, name, mt_span_of(k->tmp, len))) return MT_ERR_IO;
            copy |= (uint8_t)(1u << kind);
        }
    }
    if (k->b.written | copy) {                                /* the fabric now lives in the scratch module */
        if (cur >= 0) next.e[cur].mod = k->b.mod;
        else {
            next.e[next.n].fidx = k->b.fidx;
            next.e[next.n].mod = k->b.mod;
            next.n++;
        }
    } else if (cur >= 0) {                                    /* nothing left: drop the fabric */
        next.e[cur] = next.e[--next.n];
    } else {
        return MT_OK;                                         /* deleted a fabric that wasn't stored */
    }
    if ((e = fmap_store(k, &next))) return e;                 /* the commit point */
    k->map = next;
    /* The module the fabric left holds its old records (operational key in META): erase it now. Committed
     * already, so a failure here is not the batch's; mtp_kv_init and the next scratch_ready erase it again. */
    if (cur >= 0) (void)k->m.reset(k->m.ctx, cur_mod);
    return MT_OK;
}

/* A free fabric module still holding records: left by an aborted batch, or by a power cut between a commit and
 * the erase of the module the fabric left. */
static bool mod_dirty(mtp_kv *k, unsigned mod)
{
    for (unsigned kind = 1; kind <= MTP_FKIND_MAX; kind++) {
        char name[MTP_NAME_MAX + 1];
        size_t len;
        mtp_kv_name((uint16_t)kind, name);
        if (k->m.get(k->m.ctx, mod, name, mt_buf_of(k->tmp, MTP_VALUE_MAX), &len) != MT_ERR_NOT_FOUND) return true;
    }
    return false;
}

static void scrub_free_mods(mtp_kv *k)
{
    unsigned used = 0;
    for (unsigned i = 0; i < k->map.n; i++) used |= 1u << k->map.e[i].mod;
    for (unsigned mod = 0; mod < MTP_FMODS; mod++)
        if (!(used & (1u << mod)) && mod_dirty(k, MTP_MOD_F0 + mod)) (void)k->m.reset(k->m.ctx, MTP_MOD_F0 + mod);
}

/* ---- mt_kv_ops ---- */

static mt_err kv_get(void *ctx, uint16_t key, mt_buf out, size_t *len)
{
    mtp_kv *k = ctx;
    char name[MTP_NAME_MAX + 1];
    unsigned mod;
    mt_err e;
    mtp_kv_name(key, name);
    if (fidx_of(key) == 0) {
        const mtp_small *d = small_find(k->defer, k->n_defer, key);
        if (d) {
            if (d->del) return MT_ERR_NOT_FOUND;
            if (d->len > out.cap) return MT_ERR_BUFFER_TOO_SMALL;
            if (d->len) memcpy(out.p, d->val, d->len);
            *len = d->len;
            return MT_OK;
        }
        mod = mtp_kv_small_module(key);
    } else {
        int i = fmap_find(&k->map, fidx_of(key));
        if (i < 0 || kind_of(key) < 1 || kind_of(key) > MTP_FKIND_MAX) return MT_ERR_NOT_FOUND;
        mod = MTP_MOD_F0 + k->map.e[i].mod;
    }
    e = k->m.get(k->m.ctx, mod, name, out, len);
    return e == MT_OK || e == MT_ERR_NOT_FOUND || e == MT_ERR_BUFFER_TOO_SMALL ? e : MT_ERR_IO;
}

static mt_err kv_set(void *ctx, uint16_t key, mt_span val)
{
    mtp_kv *k = ctx;
    return fidx_of(key) ? fab_set(k, key, val) : stage_small(k, key, false, val);
}

static mt_err kv_del(void *ctx, uint16_t key)
{
    mtp_kv *k = ctx;
    return fidx_of(key) ? fab_del(k, key) : stage_small(k, key, true, mt_span_of(NULL, 0));
}

static mt_err kv_finish(void *ctx, bool apply)
{
    mtp_kv *k = ctx;
    mt_err e = MT_OK;
    if (apply) {
        if (k->b.bad) e = MT_ERR_IO;
        else if (k->b.fidx) e = fab_commit(k);
        else {
            for (unsigned i = 0; i < k->b.n_small; i++) {
                mt_err e1 = small_apply(k, &k->b.small[i]);
                if (!e) e = e1;
            }
        }
    }
    /* a dropped fabric batch leaves its records (a staged operational key) in the scratch: erase them. After a
     * failed commit the IDX write may still have landed, so that case is left to the boot-time scrub. */
    if (!apply && k->b.fidx && k->b.emptied) (void)k->m.reset(k->m.ctx, MTP_MOD_F0 + k->b.mod);
    memset(&k->b, 0, sizeof k->b);
    return e;
}

mt_err mtp_kv_init(mtp_kv *k, const mtp_mods *m, uint8_t *tmp)
{
    uint8_t buf[FMAP_MAX_BYTES];
    size_t len = 0;
    mt_err e;
    memset(k, 0, sizeof *k);
    k->m = *m;
    k->tmp = tmp;
    k->ops.ctx = k;
    k->ops.get = kv_get;
    k->ops.set = kv_set;
    k->ops.del = kv_del;
    k->ops.finish = kv_finish;
    e = k->m.get(k->m.ctx, MTP_MOD_NODE, MTP_NAME_INDEX, mt_buf_of(buf, sizeof buf), &len);
    if (e == MT_ERR_NOT_FOUND) {
        scrub_free_mods(k);
        return MT_OK;
    }
    if (e == MT_ERR_BUFFER_TOO_SMALL) return MT_ERR_INVALID;
    if (e) return MT_ERR_IO;
    if ((e = mtp_fmap_decode(&k->map, buf, len))) return e;
    scrub_free_mods(k);
    return MT_OK;
}

void mtp_kv_set_busy(mtp_kv *k, bool (*busy)(void *ctx), void *ctx)
{
    k->busy = busy;
    k->busy_ctx = ctx;
}

bool mtp_kv_deferred(const mtp_kv *k) { return k->n_defer != 0; }
unsigned mtp_kv_fabrics(const mtp_kv *k) { return k->map.n; }

mt_err mtp_kv_flush(mtp_kv *k)
{
    mt_err e = MT_OK;
    for (unsigned i = 0; i < k->n_defer;) {
        if (small_write(k, &k->defer[i])) { e = MT_ERR_IO; i++; continue; }
        k->defer[i] = k->defer[--k->n_defer];
    }
    return e;
}
