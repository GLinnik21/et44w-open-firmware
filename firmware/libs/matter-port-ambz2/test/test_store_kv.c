/* Host tests of store_kv (RAM module store with power-cut injection) and boot_policy. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "boot_policy.h"
#include "flash_guard.h"
#include "store_kv.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fails++; fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); } } while (0)

/* ---- fake module store: 6 modules, 7 variables of <= MTP_VALUE_MAX bytes each (the DCT2 geometry) ---- */
#define FAKE_VARS 7
typedef struct { bool used; char name[MTP_NAME_MAX + 1]; size_t len; uint8_t v[MTP_VALUE_MAX]; } fvar;
typedef struct {
    fvar mod[MTP_N_MODS][FAKE_VARS];
    long budget;       /* mutating ops left before the power cut; < 0 = unlimited */
    unsigned writes;   /* mutating ops done */
    unsigned resets;
} fake;

static bool fk_alive(fake *f)
{
    if (f->budget == 0) return false;
    if (f->budget > 0) f->budget--;
    f->writes++;
    return true;
}

static fvar *fk_find(fake *f, unsigned mod, const char *name)
{
    for (int i = 0; i < FAKE_VARS; i++)
        if (f->mod[mod][i].used && !strcmp(f->mod[mod][i].name, name)) return &f->mod[mod][i];
    return NULL;
}

static mt_err fk_get(void *ctx, unsigned mod, const char *name, mt_buf out, size_t *len)
{
    fvar *v = fk_find(ctx, mod, name);
    if (mod >= MTP_N_MODS) return MT_ERR_IO;
    if (!v) return MT_ERR_NOT_FOUND;
    if (v->len > out.cap) return MT_ERR_BUFFER_TOO_SMALL;
    memcpy(out.p, v->v, v->len);
    *len = v->len;
    return MT_OK;
}

static mt_err fk_set(void *ctx, unsigned mod, const char *name, mt_span val)
{
    fake *f = ctx;
    fvar *v;
    if (mod >= MTP_N_MODS || strlen(name) > MTP_NAME_MAX || val.len > MTP_VALUE_MAX) return MT_ERR_IO;
    if (!fk_alive(f)) return MT_ERR_IO;
    v = fk_find(f, mod, name);
    for (int i = 0; !v && i < FAKE_VARS; i++) if (!f->mod[mod][i].used) v = &f->mod[mod][i];
    if (!v) return MT_ERR_IO;
    v->used = true;
    strcpy(v->name, name);
    v->len = val.len;
    memcpy(v->v, val.p, val.len);
    return MT_OK;
}

static mt_err fk_del(void *ctx, unsigned mod, const char *name)
{
    fake *f = ctx;
    fvar *v;
    if (mod >= MTP_N_MODS || !fk_alive(f)) return MT_ERR_IO;
    if ((v = fk_find(f, mod, name))) v->used = false;
    return MT_OK;
}

static mt_err fk_reset(void *ctx, unsigned mod)
{
    fake *f = ctx;
    if (mod >= MTP_N_MODS || !fk_alive(f)) return MT_ERR_IO;
    memset(f->mod[mod], 0, sizeof f->mod[mod]);
    f->resets++;
    return MT_OK;
}

static fake F;
static uint8_t tmp[MTP_VALUE_MAX];

static void boot(mtp_kv *k)
{
    mtp_mods m = { &F, fk_get, fk_set, fk_del, fk_reset };
    F.budget = -1;
    CHECK(mtp_kv_init(k, &m, tmp) == MT_OK);
}

static void wipe(mtp_kv *k)
{
    memset(&F, 0, sizeof F);
    boot(k);
}

#define FK(i, kind) ((uint16_t)(((i) << 8) | (kind)))

/* Record contents: fabric i, kind, generation g; length varies with kind so copies are checked byte-exactly. */
static size_t rec(uint8_t *out, unsigned i, unsigned kind, unsigned g)
{
    size_t len = kind == 5 ? 432 : kind == 4 ? 208 : 380 + kind;
    for (size_t j = 0; j < len; j++) out[j] = (uint8_t)(i * 31 + kind * 7 + g * 13 + j);
    return len;
}

static mt_err put_fabric(mtp_kv *k, unsigned i, unsigned g)
{
    uint8_t b[MTP_VALUE_MAX];
    for (unsigned kind = 1; kind <= 5; kind++) {
        size_t n = rec(b, i, kind, g);
        mt_err e = k->ops.set(k, FK(i, kind), mt_span_of(b, n));
        if (e) { k->ops.finish(k, false); return e; }
    }
    return k->ops.finish(k, true);
}

static mt_err erase_fabric(mtp_kv *k, unsigned i)
{
    for (unsigned kind = 1; kind <= 5; kind++) {
        mt_err e = k->ops.del(k, FK(i, kind));
        if (e) { k->ops.finish(k, false); return e; }
    }
    return k->ops.finish(k, true);
}

/* 1: fabric i holds generation g in every kind, except kind `acl_g_kind` which holds acl_g (0 = none). */
static bool fabric_is(mtp_kv *k, unsigned i, unsigned g, unsigned acl_g)
{
    uint8_t want[MTP_VALUE_MAX], got[MTP_VALUE_MAX];
    for (unsigned kind = 1; kind <= 5; kind++) {
        size_t n = rec(want, i, kind, kind == 5 && acl_g ? acl_g : g), len = 0;
        if (k->ops.get(k, FK(i, kind), mt_buf_of(got, sizeof got), &len) != MT_OK) return false;
        if (len != n || memcmp(got, want, n)) return false;
    }
    return true;
}

static bool fabric_absent(mtp_kv *k, unsigned i)
{
    uint8_t got[MTP_VALUE_MAX];
    size_t len;
    for (unsigned kind = 1; kind <= 5; kind++)
        if (k->ops.get(k, FK(i, kind), mt_buf_of(got, sizeof got), &len) != MT_ERR_NOT_FOUND) return false;
    return true;
}

static bool mod_empty(unsigned mod)
{
    for (int i = 0; i < FAKE_VARS; i++) if (F.mod[mod][i].used) return false;
    return true;
}

static int fmap_index(const mtp_kv *k, unsigned fidx)
{
    for (unsigned i = 0; i < k->map.n; i++) if (k->map.e[i].fidx == fidx) return (int)i;
    return -1;
}

static bool free_mods_empty(const mtp_kv *k)
{
    unsigned used = 0;
    for (unsigned i = 0; i < k->map.n; i++) used |= 1u << k->map.e[i].mod;
    for (unsigned mod = 0; mod < MTP_FMODS; mod++)
        if (!(used & (1u << mod)) && !mod_empty(MTP_MOD_F0 + mod)) return false;
    return true;
}

static void put_wifi(void)
{
    CHECK(fk_set(&F, MTP_MOD_NODE, MTP_NAME_WIFI, mt_span_of("ssid+pass", 9)) == MT_OK);
}

static bool wifi_ok(void)
{
    fvar *v = fk_find(&F, MTP_MOD_NODE, MTP_NAME_WIFI);
    return v && v->len == 9 && !memcmp(v->v, "ssid+pass", 9);
}

/* ---- tests ---- */

static void test_helpers(void)
{
    char name[MTP_NAME_MAX + 1];
    mtp_fmap m = { 2, { { 1, 0 }, { 7, 2 } } }, d;
    uint8_t b[16];
    mtp_kv_name(FK(9, 5), name);
    CHECK(!strcmp(name, "k05"));
    mtp_kv_name(0x0023, name);
    CHECK(!strcmp(name, "k23"));
    CHECK(mtp_kv_small_module(0x0023) == MTP_MOD_BOOT);
    CHECK(mtp_kv_small_module(0x0020) == MTP_MOD_NODE);
    CHECK(mtp_kv_small_module(0x0021) == MTP_MOD_NODE);

    size_t n = mtp_fmap_encode(&m, b, sizeof b);
    CHECK(n == 6);
    CHECK(mtp_fmap_decode(&d, b, n) == MT_OK && d.n == 2 && d.e[1].fidx == 7 && d.e[1].mod == 2);
    CHECK(mtp_fmap_encode(&m, b, 5) == 0);
    CHECK(mtp_fmap_decode(&d, b, n - 1) == MT_ERR_INVALID && d.n == 0);
    b[4] = 1;                                                     /* duplicate fabric index */
    CHECK(mtp_fmap_decode(&d, b, n) == MT_ERR_INVALID);
    b[4] = 7; b[5] = 0;                                           /* duplicate module */
    CHECK(mtp_fmap_decode(&d, b, n) == MT_ERR_INVALID);
    b[5] = 4;                                                     /* module out of range */
    CHECK(mtp_fmap_decode(&d, b, n) == MT_ERR_INVALID);
    b[5] = 2; b[2] = 0;                                           /* fabric index 0 */
    CHECK(mtp_fmap_decode(&d, b, n) == MT_ERR_INVALID);
    b[2] = 1; b[0] = 2;                                           /* version */
    CHECK(mtp_fmap_decode(&d, b, n) == MT_ERR_INVALID);
    uint8_t four[10] = { 1, 4, 1, 0, 2, 1, 3, 2, 4, 3 };          /* 4 fabrics: no scratch left */
    CHECK(mtp_fmap_decode(&d, four, sizeof four) == MT_ERR_INVALID);
    uint8_t empty[2] = { 1, 0 };
    CHECK(mtp_fmap_decode(&d, empty, 2) == MT_OK && d.n == 0);
}

static void test_node_records(void)
{
    mtp_kv k;
    uint8_t b[128];
    size_t len;
    wipe(&k);
    CHECK(k.ops.get(&k, 0x0020, mt_buf_of(b, sizeof b), &len) == MT_ERR_NOT_FOUND);
    CHECK(k.ops.set(&k, 0x0020, mt_span_of("label", 5)) == MT_OK);
    CHECK(k.ops.set(&k, 0x0023, mt_span_of("boot1", 5)) == MT_OK);
    CHECK(k.ops.get(&k, 0x0020, mt_buf_of(b, sizeof b), &len) == MT_ERR_NOT_FOUND); /* staged, not applied */
    CHECK(k.ops.finish(&k, true) == MT_OK);
    CHECK(fk_find(&F, MTP_MOD_BOOT, "k23") && fk_find(&F, MTP_MOD_NODE, "k20"));
    boot(&k);
    CHECK(k.ops.get(&k, 0x0020, mt_buf_of(b, sizeof b), &len) == MT_OK && len == 5 && !memcmp(b, "label", 5));
    CHECK(k.ops.get(&k, 0x0020, mt_buf_of(b, 4), &len) == MT_ERR_BUFFER_TOO_SMALL);
    CHECK(k.ops.set(&k, 0x0020, mt_span_of("x", 1)) == MT_OK);
    CHECK(k.ops.finish(&k, false) == MT_OK);
    CHECK(k.ops.get(&k, 0x0020, mt_buf_of(b, sizeof b), &len) == MT_OK && len == 5);
    CHECK(k.ops.del(&k, 0x0020) == MT_OK && k.ops.finish(&k, true) == MT_OK);
    CHECK(k.ops.get(&k, 0x0020, mt_buf_of(b, sizeof b), &len) == MT_ERR_NOT_FOUND);
    CHECK(k.ops.del(&k, 0x0021) == MT_OK && k.ops.finish(&k, true) == MT_OK);       /* absent delete */
    uint8_t big[MTP_SMALL_MAX + 1] = { 0 };
    CHECK(k.ops.set(&k, 0x0021, mt_span_of(big, sizeof big)) == MT_ERR_BUFFER_TOO_SMALL);
    CHECK(k.ops.finish(&k, false) == MT_OK);
}

static bool busy_flag;
static bool is_busy(void *ctx) { (void)ctx; return busy_flag; }

static void test_deferral(void)
{
    mtp_kv k;
    uint8_t b[128];
    size_t len;
    wipe(&k);
    mtp_kv_set_busy(&k, is_busy, NULL);
    busy_flag = true;
    unsigned w = F.writes;
    CHECK(k.ops.set(&k, 0x0023, mt_span_of("boot1", 5)) == MT_OK && k.ops.finish(&k, true) == MT_OK);
    CHECK(F.writes == w && mtp_kv_deferred(&k));
    CHECK(k.ops.get(&k, 0x0023, mt_buf_of(b, sizeof b), &len) == MT_OK && len == 5);  /* applied view */
    CHECK(k.ops.set(&k, 0x0023, mt_span_of("boot2", 5)) == MT_OK && k.ops.finish(&k, true) == MT_OK);
    CHECK(k.n_defer == 1);                                                             /* coalesced */
    CHECK(k.ops.del(&k, 0x0020) == MT_OK && k.ops.finish(&k, true) == MT_OK);
    CHECK(k.ops.get(&k, 0x0020, mt_buf_of(b, sizeof b), &len) == MT_ERR_NOT_FOUND);
    CHECK(k.ops.set(&k, 0x0021, mt_span_of("r", 1)) == MT_OK && k.ops.finish(&k, true) == MT_OK);
    CHECK(k.n_defer == 3 && F.writes == w);
    /* queue full: a fourth key... there are only three node keys in use, so reuse an unused one */
    CHECK(k.ops.set(&k, 0x0022, mt_span_of("q", 1)) == MT_OK && k.ops.finish(&k, true) == MT_OK);
    CHECK(F.writes == w + 1 && fk_find(&F, MTP_MOD_NODE, "k22"));                      /* written at once */
    /* power cut before the flush: the deferred records are lost, nothing else */
    {
        mtp_kv k2;
        boot(&k2);
        CHECK(k2.ops.get(&k2, 0x0023, mt_buf_of(b, sizeof b), &len) == MT_ERR_NOT_FOUND);
    }
    busy_flag = false;
    CHECK(mtp_kv_flush(&k) == MT_OK && !mtp_kv_deferred(&k));
    CHECK(fk_get(&F, MTP_MOD_BOOT, "k23", mt_buf_of(b, sizeof b), &len) == MT_OK && !memcmp(b, "boot2", 5));
    CHECK(fk_find(&F, MTP_MOD_NODE, "k21") != NULL);
    /* not busy: written at once */
    w = F.writes;
    CHECK(k.ops.set(&k, 0x0023, mt_span_of("boot3", 5)) == MT_OK && k.ops.finish(&k, true) == MT_OK);
    CHECK(F.writes == w + 1 && !mtp_kv_deferred(&k));
}

static void test_fabrics(void)
{
    mtp_kv k;
    uint8_t b[MTP_VALUE_MAX];
    size_t len;
    wipe(&k);
    put_wifi();
    CHECK(fabric_absent(&k, 1));
    CHECK(put_fabric(&k, 1, 1) == MT_OK);
    CHECK(fabric_is(&k, 1, 1, 0) && mtp_kv_fabrics(&k) == 1);
    boot(&k);
    CHECK(fabric_is(&k, 1, 1, 0) && mtp_kv_fabrics(&k) == 1);
    CHECK(fabric_absent(&k, 2));
    CHECK(k.ops.get(&k, FK(1, 6), mt_buf_of(b, sizeof b), &len) == MT_ERR_NOT_FOUND);
    CHECK(k.ops.get(&k, FK(1, 8), mt_buf_of(b, sizeof b), &len) == MT_ERR_NOT_FOUND);
    CHECK(k.ops.get(&k, FK(1, 5), mt_buf_of(b, 10), &len) == MT_ERR_BUFFER_TOO_SMALL);

    /* ACL-only update: the other kinds are carried over; the live module is untouched until the commit and
     * erased after it (the fabric moved to the scratch) */
    unsigned live = MTP_MOD_F0 + k.map.e[0].mod;
    fvar before[FAKE_VARS];
    memcpy(before, F.mod[live], sizeof before);
    size_t n = rec(b, 1, 5, 2);
    CHECK(k.ops.set(&k, FK(1, 5), mt_span_of(b, n)) == MT_OK);
    CHECK(fabric_is(&k, 1, 1, 0));                                  /* not applied before finish */
    CHECK(!memcmp(before, F.mod[live], sizeof before));
    CHECK(k.ops.finish(&k, true) == MT_OK);
    CHECK((unsigned) (MTP_MOD_F0 + k.map.e[0].mod) != live && mod_empty(live));
    CHECK(fabric_is(&k, 1, 1, 2));
    boot(&k);
    CHECK(fabric_is(&k, 1, 1, 2));

    /* dropped batch: its scratch is erased again */
    n = rec(b, 1, 5, 3);
    CHECK(k.ops.set(&k, FK(1, 5), mt_span_of(b, n)) == MT_OK);
    unsigned scratch = MTP_MOD_F0 + k.b.mod;
    CHECK(!mod_empty(scratch));
    CHECK(k.ops.finish(&k, false) == MT_OK);
    CHECK(mod_empty(scratch));
    CHECK(fabric_is(&k, 1, 1, 2));
    boot(&k);
    CHECK(fabric_is(&k, 1, 1, 2));

    /* a full update in place of the old one, a second and third fabric, then the limit */
    CHECK(put_fabric(&k, 1, 4) == MT_OK && fabric_is(&k, 1, 4, 0));
    CHECK(put_fabric(&k, 9, 1) == MT_OK && put_fabric(&k, 254, 1) == MT_OK);
    CHECK(mtp_kv_fabrics(&k) == 3);
    CHECK(put_fabric(&k, 3, 1) == MT_ERR_BUFFER_TOO_SMALL && fabric_absent(&k, 3));
    CHECK(put_fabric(&k, 9, 2) == MT_OK);                          /* updates still work when full */
    boot(&k);
    CHECK(fabric_is(&k, 1, 4, 0) && fabric_is(&k, 9, 2, 0) && fabric_is(&k, 254, 1, 0) && fabric_absent(&k, 3));

    /* RemoveFabric: the five deletes; its module (operational key in META) is erased, not just unlisted */
    unsigned mod9 = MTP_MOD_F0 + k.map.e[fmap_index(&k, 9)].mod;
    CHECK(!mod_empty(mod9));
    CHECK(erase_fabric(&k, 9) == MT_OK && fabric_absent(&k, 9) && mtp_kv_fabrics(&k) == 2);
    CHECK(mod_empty(mod9));
    boot(&k);
    CHECK(fabric_absent(&k, 9) && fabric_is(&k, 1, 4, 0) && fabric_is(&k, 254, 1, 0));
    /* deleting a fabric that isn't stored writes nothing */
    unsigned w = F.writes;
    CHECK(erase_fabric(&k, 9) == MT_OK && F.writes == w);
    /* partial delete keeps the rest */
    CHECK(k.ops.del(&k, FK(1, 2)) == MT_OK && k.ops.finish(&k, true) == MT_OK);
    CHECK(k.ops.get(&k, FK(1, 2), mt_buf_of(b, sizeof b), &len) == MT_ERR_NOT_FOUND);
    CHECK(k.ops.get(&k, FK(1, 3), mt_buf_of(b, sizeof b), &len) == MT_OK);
    CHECK(fabric_is(&k, 254, 1, 0) && wifi_ok());

    /* oversize record */
    uint8_t big[MTP_VALUE_MAX + 1] = { 0 };
    CHECK(k.ops.set(&k, FK(1, 1), mt_span_of(big, sizeof big)) == MT_ERR_BUFFER_TOO_SMALL);
    CHECK(k.ops.finish(&k, false) == MT_OK);
}

static void test_mixed_batches(void)
{
    mtp_kv k;
    wipe(&k);
    CHECK(put_fabric(&k, 1, 1) == MT_OK && put_fabric(&k, 2, 1) == MT_OK);
    CHECK(k.ops.set(&k, FK(1, 5), mt_span_of("a", 1)) == MT_OK);
    CHECK(k.ops.set(&k, FK(2, 5), mt_span_of("a", 1)) == MT_ERR_INVALID);
    CHECK(k.ops.set(&k, 0x0020, mt_span_of("a", 1)) == MT_ERR_INVALID);
    CHECK(k.ops.del(&k, FK(2, 5)) == MT_ERR_INVALID);
    CHECK(k.ops.del(&k, FK(7, 5)) == MT_OK);                        /* absent fabric: no-op */
    CHECK(k.ops.finish(&k, false) == MT_OK);
    CHECK(k.ops.set(&k, 0x0020, mt_span_of("a", 1)) == MT_OK);
    CHECK(k.ops.set(&k, FK(1, 5), mt_span_of("a", 1)) == MT_ERR_INVALID);
    CHECK(k.ops.finish(&k, false) == MT_OK);
    CHECK(k.ops.set(&k, FK(1, 0), mt_span_of("a", 1)) != MT_OK);    /* kind 0 does not exist */
    CHECK(k.ops.finish(&k, false) == MT_OK);
    CHECK(fabric_is(&k, 1, 1, 0) && fabric_is(&k, 2, 1, 0));
}

/* Runs `op` against a store prepared by `prep`, cut after every possible number of writes; after each cut the
 * rebooted store must hold the old or the new state, and the bystanders must be intact. The IDX write is the one
 * commit point: every cut before it reads as old and fails the op, every cut after it (only the erase of the module
 * the fabric left follows) reads as new and succeeds. After the reboot no free module holds records. */
typedef void (*prep_fn)(mtp_kv *k);
typedef mt_err (*op_fn)(mtp_kv *k);
typedef int (*state_fn)(mtp_kv *k);  /* 0 = old, 1 = new, -1 = neither */

static void cut_test(const char *what, prep_fn prep, op_fn op, state_fn state)
{
    mtp_kv k;
    unsigned total, olds = 0, news = 0;
    wipe(&k);
    prep(&k);
    unsigned w0 = F.writes;
    CHECK(op(&k) == MT_OK);
    total = F.writes - w0;
    CHECK(state(&k) == 1);
    CHECK(free_mods_empty(&k));
    for (unsigned cut = 0; cut <= total; cut++) {
        wipe(&k);
        prep(&k);
        F.budget = cut;
        mt_err e = op(&k);
        boot(&k);
        int s = state(&k);
        if (s < 0) fprintf(stderr, "%s: cut after %u of %u writes: torn state\n", what, cut, total);
        CHECK(s >= 0);
        CHECK((e == MT_OK) == (s == 1));
        CHECK(s == 1 || !news);         /* no old state after a new one: a single flip */
        CHECK(wifi_ok());
        CHECK(free_mods_empty(&k));     /* stale records are erased at boot */
        if (s == 0) olds++; else news++;
        /* the store keeps working after the cut */
        CHECK(put_fabric(&k, 200, 1) == MT_OK && fabric_is(&k, 200, 1, 0));
    }
    CHECK(olds >= 1 && news >= 1 && news <= 2);  /* at most the erase follows the commit */
}

static void prep_one(mtp_kv *k) { put_wifi(); CHECK(put_fabric(k, 1, 1) == MT_OK); }
static void prep_two(mtp_kv *k) { prep_one(k); CHECK(put_fabric(k, 5, 1) == MT_OK); }

static mt_err op_add(mtp_kv *k) { return put_fabric(k, 5, 1); }
static int st_add(mtp_kv *k)
{
    if (!fabric_is(k, 1, 1, 0)) return -1;
    return fabric_is(k, 5, 1, 0) ? 1 : fabric_absent(k, 5) ? 0 : -1;
}

static mt_err op_acl(mtp_kv *k)
{
    uint8_t b[MTP_VALUE_MAX];
    size_t n = rec(b, 5, 5, 2);
    mt_err e = k->ops.set(k, FK(5, 5), mt_span_of(b, n));
    if (e) { k->ops.finish(k, false); return e; }
    return k->ops.finish(k, true);
}
static int st_acl(mtp_kv *k)
{
    if (!fabric_is(k, 1, 1, 0)) return -1;
    return fabric_is(k, 5, 1, 2) ? 1 : fabric_is(k, 5, 1, 0) ? 0 : -1;
}

static mt_err op_update(mtp_kv *k) { return put_fabric(k, 5, 3); }
static int st_update(mtp_kv *k)
{
    if (!fabric_is(k, 1, 1, 0)) return -1;
    return fabric_is(k, 5, 3, 0) ? 1 : fabric_is(k, 5, 1, 0) ? 0 : -1;
}

static mt_err op_remove(mtp_kv *k) { return erase_fabric(k, 5); }
static int st_remove(mtp_kv *k)
{
    if (!fabric_is(k, 1, 1, 0)) return -1;
    return fabric_absent(k, 5) ? 1 : fabric_is(k, 5, 1, 0) ? 0 : -1;
}

static void test_boot_policy(void)
{
    CHECK(mtp_boot_reason_of(0) == 1);            /* MT_BOOT_POWER_ON */
    CHECK(mtp_boot_reason_of(2) == 4);            /* MT_BOOT_HW_WATCHDOG */
    CHECK(mtp_boot_reason_of(3) == 4);
    CHECK(mtp_boot_reason_of(1) == 6);            /* MT_BOOT_SW_RESET */
    CHECK(mtp_boot_reason_of(4) == 0);
    uint8_t c = 0;
    c = mtp_safe_on_boot(c, 2); CHECK(c == 1 && !mtp_safe_skip(c));
    c = mtp_safe_on_boot(c, 1); CHECK(c == 1);    /* software reset: unchanged */
    c = mtp_safe_on_boot(c, 2); CHECK(c == 2 && !mtp_safe_skip(c));
    c = mtp_safe_on_boot(c, 2); CHECK(c == 3 && mtp_safe_skip(c));
    c = mtp_safe_on_boot(c, 0); CHECK(c == 0);    /* power-on clears */
    CHECK(mtp_safe_on_boot(255, 2) == 255);
    CHECK(mtp_safe_on_stable() == 0);
}

/* The DCT flash guard, with the real partition numbers: matter = 0x1EA000 + 0xC000; kv and ota_state below it,
 * sdk_reserved (BT FTL) above. */
static void test_flash_guard(void)
{
    const uint32_t B = 0x1EA000u, S = 0xC000u, E = B + S;
    /* erase: dct_flash_erase(addr, len) erases ((len - 1) >> 12) + 1 sectors */
    CHECK(mtp_guard_erase_ok(B, 1, B, S));
    CHECK(mtp_guard_erase_ok(B, 0x1000, B, S));
    CHECK(mtp_guard_erase_ok(B, S, B, S));                    /* the whole region */
    CHECK(mtp_guard_erase_ok(E - 0x1000, 0x1000, B, S));      /* last sector */
    CHECK(mtp_guard_erase_ok(E - 0x1000, 1, B, S));
    CHECK(!mtp_guard_erase_ok(E - 0x1000, 0x1001, B, S));     /* one sector past the end */
    CHECK(!mtp_guard_erase_ok(B, S + 1, B, S));
    CHECK(!mtp_guard_erase_ok(E, 0x1000, B, S));              /* first sector after the region */
    CHECK(!mtp_guard_erase_ok(B, 0, B, S));                   /* len 0 = 2^20 sectors in lib_dct.a */
    CHECK(!mtp_guard_erase_ok(B + 0x1000, 0, B, S));
    CHECK(!mtp_guard_erase_ok(B, 0xFFFFF001u, B, S));         /* used to round up to a span of 0 */
    CHECK(!mtp_guard_erase_ok(B, 0xFFFFFFFFu, B, S));
    CHECK(!mtp_guard_erase_ok(B + 0x800, 0x100, B, S));       /* misaligned: would erase the sector before */
    CHECK(!mtp_guard_erase_ok(B - 0x1000, 0x1000, B, S));     /* ota_state is 0x1E9000 */
    CHECK(!mtp_guard_erase_ok(0x1E9000u, 0x2000, B, S));
    CHECK(!mtp_guard_erase_ok(0x1D1000u, 0x1000, B, S));      /* kv */
    CHECK(!mtp_guard_erase_ok(0x1FC000u, 0x1000, B, S));      /* BT FTL in sdk_reserved */
    CHECK(!mtp_guard_erase_ok(0, 0x1000, B, S));
    /* write */
    CHECK(mtp_guard_write_ok(B, 1, B, S));
    CHECK(mtp_guard_write_ok(B, S, B, S));
    CHECK(mtp_guard_write_ok(E - 1, 1, B, S));
    CHECK(mtp_guard_write_ok(B + 0x10, 0, B, S));
    CHECK(!mtp_guard_write_ok(E - 1, 2, B, S));
    CHECK(!mtp_guard_write_ok(E, 0, B, S));
    CHECK(!mtp_guard_write_ok(E, 1, B, S));
    CHECK(!mtp_guard_write_ok(B - 1, 1, B, S));
    CHECK(!mtp_guard_write_ok(B - 1, 2, B, S));
    CHECK(!mtp_guard_write_ok(B + 4, 0xFFFFFFFFu, B, S));    /* addr + len wraps */
    CHECK(!mtp_guard_write_ok(0xFFFFFFF0u, 0x20, B, S));
    CHECK(!mtp_guard_write_ok(0x1E9000u, 4, B, S));
}

static void test_store_hold(void)
{
    CHECK(mtp_store_hold_ms(0) == 0);                         /* power-on */
    CHECK(mtp_store_hold_ms(1) == 0);                         /* software reset (OTA install, rollback) */
    CHECK(mtp_store_hold_ms(2) == MTP_WDOG_HOLD_MS);          /* watchdog: fault or hang */
    CHECK(mtp_store_hold_ms(3) == MTP_WDOG_HOLD_MS);
    CHECK(MTP_WDOG_HOLD_MS >= 30000u && MTP_WDOG_HOLD_MS < MTP_SAFE_STABLE_MS);
}

void test_mdns_sub(int *fails);
void test_rescue(int *fails);
void test_wifi_sec(int *fails);

int main(void)
{
    test_mdns_sub(&fails);
    test_rescue(&fails);
    test_wifi_sec(&fails);
    test_helpers();
    test_node_records();
    test_deferral();
    test_fabrics();
    test_mixed_batches();
    cut_test("add", prep_one, op_add, st_add);
    cut_test("acl", prep_two, op_acl, st_acl);
    cut_test("update", prep_two, op_update, st_update);
    cut_test("remove", prep_two, op_remove, st_remove);
    test_boot_policy();
    test_flash_guard();
    test_store_hold();
    if (fails) { printf("matter-port-ambz2: %d FAILED\n", fails); return 1; }
    printf("matter-port-ambz2: all tests passed\n");
    return 0;
}
