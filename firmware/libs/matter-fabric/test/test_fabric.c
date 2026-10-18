/* Host tests for matter-fabric.
 * Official vectors: the compressed fabric ID example of the Matter spec (4.3.2.2: root key 044a9f42...,
 * fabric ID 2906C908D115D362 -> 87E1B004E235A130) and the operational-IPK derivations of connectedhomeip
 * TestGroupOperationalCredentials.cpp / TestGroupDataProvider.cpp (epoch key -> operational key, salt =
 * that compressed fabric ID), as collected in rs-matter group_keys.rs. Certificates: the connectedhomeip
 * CHIPCert test certificates of matter-cert/test/vectors.h. Not official: the destination-ID value (HMAC
 * computed independently with Python for Root01 / Node01_01) and the ACL wire bytes (hand-encoded from the
 * Access Control cluster struct). Storage: an in-RAM kv fake with staged and applied halves (get sees only
 * the applied state, like the real port) and failure injection. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mt_fabric.h"
#include "vectors.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

/* ---- kv fake ---- */

#define KV_N 40
#define KV_CAP 512
typedef struct { uint16_t key, len; uint8_t d[KV_CAP]; bool used; } ent;
typedef struct {
    ent applied[KV_N], staged[KV_N];
    bool dirty;
    int fail_in;                 /* >0: the n-th set/del/finish(apply) from now fails with MT_ERR_IO */
    int applies, drops;
} fake;

static ent *kfind(ent *a, uint16_t key)
{
    for (int i = 0; i < KV_N; i++) if (a[i].used && a[i].key == key) return &a[i];
    return NULL;
}
static bool tick(fake *k) { return k->fail_in > 0 && --k->fail_in == 0; }
static void touch(fake *k) { if (!k->dirty) { memcpy(k->staged, k->applied, sizeof k->applied); k->dirty = true; } }

static mt_err f_get(void *c, uint16_t key, mt_buf out, size_t *len)
{
    fake *k = c;
    ent *e = kfind(k->applied, key);
    if (!e) return MT_ERR_NOT_FOUND;
    if (e->len > out.cap) return MT_ERR_BUFFER_TOO_SMALL;
    memcpy(out.p, e->d, e->len);
    *len = e->len;
    return MT_OK;
}
static mt_err f_set(void *c, uint16_t key, mt_span v)
{
    fake *k = c;
    if (tick(k)) return MT_ERR_IO;
    if (v.len > KV_CAP) return MT_ERR_BUFFER_TOO_SMALL;
    touch(k);
    ent *e = kfind(k->staged, key);
    for (int i = 0; !e && i < KV_N; i++) if (!k->staged[i].used) e = &k->staged[i];
    if (!e) return MT_ERR_IO;
    e->used = true; e->key = key; e->len = (uint16_t)v.len;
    memcpy(e->d, v.p, v.len);
    return MT_OK;
}
static mt_err f_del(void *c, uint16_t key)
{
    fake *k = c;
    if (tick(k)) return MT_ERR_IO;
    touch(k);
    ent *e = kfind(k->staged, key);
    if (e) e->used = false;
    return MT_OK;
}
static mt_err f_finish(void *c, bool apply)
{
    fake *k = c;
    bool fail = apply && tick(k);
    if (apply && !fail && k->dirty) { memcpy(k->applied, k->staged, sizeof k->applied); k->applies++; }
    else k->drops++;
    k->dirty = false;
    return fail ? MT_ERR_IO : MT_OK;
}
static mt_kv_ops ops_of(fake *k)
{
    mt_kv_ops o = { k, f_get, f_set, f_del, f_finish };
    return o;
}
static bool has(fake *k, unsigned idx, int kind) { return kfind(k->applied, MT_FKEY(idx, kind)) != NULL; }
static unsigned nkeys(fake *k) { unsigned n = 0; for (int i = 0; i < KV_N; i++) n += k->applied[i].used; return n; }

/* ---- fixtures ---- */

#define NVECS (sizeof VECS / sizeof VECS[0])
static const struct vec *vec(const char *name)
{
    for (size_t i = 0; i < NVECS; i++) if (!strcmp(VECS[i].name, name)) return &VECS[i];
    printf("no vector %s\n", name);
    exit(2);
}
static mt_span tl(const char *name) { const struct vec *v = vec(name); return mt_span_of(v->tlv, v->tlv_len); }
static const uint8_t *pubof(const char *name) { return vec(name)->pub; }

static uint8_t scratch_mem[MT_FABRIC_SCRATCH];
static mt_buf scratch(void) { return mt_buf_of(scratch_mem, sizeof scratch_mem); }
static const uint8_t EPOCH[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
#define NOW 700000000u
#define ADMIN 0x112233445566ull

static mt_fabric_table T;
static fake K;
static mt_kv_ops OPS;

static void fresh(void)
{
    memset(&K, 0, sizeof K);
    OPS = ops_of(&K);
    mt_fabric_init(&T, &OPS);
}

static mt_err stage_all(const char *root, const char *noc, const char *icac, uint32_t now, uint8_t seed, uint8_t *idx)
{
    uint8_t priv[32];
    memset(priv, seed, sizeof priv);
    mt_fabric_abort(&T);
    mt_err e = mt_fabric_stage_key(&T, priv, pubof(noc));
    if (e) return e;
    if ((e = mt_fabric_stage_rcac(&T, tl(root)))) return e;
    return mt_fabric_add_noc(&T, tl(noc), icac ? tl(icac) : mt_span_of(NULL, 0), EPOCH, ADMIN, 0xFFF1, now, scratch(), idx);
}

static bool acl_eq(const mt_acl_entry *a, const mt_acl_entry *b)
{
    if (a->privilege != b->privilege || a->auth_mode != b->auth_mode || a->n_subjects != b->n_subjects || a->n_targets != b->n_targets) return false;
    for (unsigned i = 0; i < a->n_subjects; i++) if (a->subjects[i] != b->subjects[i]) return false;
    for (unsigned i = 0; i < a->n_targets; i++)
        if (a->targets[i].cluster != b->targets[i].cluster || a->targets[i].endpoint != b->targets[i].endpoint || a->targets[i].devtype != b->targets[i].devtype) return false;
    return true;
}
static bool same(const mt_fabric *a, const mt_fabric *b)
{
    if (a->index != b->index || a->vendor_id != b->vendor_id || a->fabric_id != b->fabric_id || a->node_id != b->node_id ||
        memcmp(a->cfid, b->cfid, sizeof a->cfid) || memcmp(a->root_pub, b->root_pub, sizeof a->root_pub) ||
        memcmp(a->ipk_epoch, b->ipk_epoch, 16) || memcmp(a->ipk, b->ipk, 16) || strcmp(a->label, b->label) || a->n_acl != b->n_acl)
        return false;
    for (unsigned i = 0; i < a->n_acl; i++) if (!acl_eq(&a->acl[i], &b->acl[i])) return false;
    return true;
}

/* Reload the applied kv into a second table and compare every fabric with the live one. */
static void check_reload(void)
{
    static mt_fabric_table R;
    mt_fabric_init(&R, &OPS);
    CHECK(mt_fabric_load(&R, scratch()) == MT_OK);
    CHECK(R.skipped == 0);
    CHECK(mt_fabric_committed_count(&R) == mt_fabric_committed_count(&T));
    for (unsigned i = 0; i < MT_FABRIC_MAX; i++)
        if (T.slots[i].index) {
            const mt_fabric *r = mt_fabric_get(&R, T.slots[i].index);
            CHECK(r && same(r, &T.slots[i]));
        }
}

/* ---- identifiers ---- */

static void test_ids(void)
{
    static const uint8_t root[65] = {
        0x04, 0x4a, 0x9f, 0x42, 0xb1, 0xca, 0x48, 0x40, 0xd3, 0x72, 0x92, 0xbb, 0xc7, 0xf6, 0xa7, 0xe1, 0x1e, 0x22, 0x20, 0x0c, 0x97, 0x6f,
        0xc9, 0x00, 0xdb, 0xc9, 0x8a, 0x7a, 0x38, 0x3a, 0x64, 0x1c, 0xb8, 0x25, 0x4a, 0x2e, 0x56, 0xd4, 0xe2, 0x95, 0xa8, 0x47, 0x94, 0x3b,
        0x4e, 0x38, 0x97, 0xc4, 0xa7, 0x73, 0xe9, 0x30, 0x27, 0x7b, 0x4d, 0x9f, 0xbe, 0xde, 0x8a, 0x05, 0x26, 0x86, 0xbf, 0xac, 0xfa };
    static const uint8_t cfid[8] = { 0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30 };
    uint8_t out[8], bad[65];
    CHECK(mt_fabric_compress_id(root, 0x2906C908D115D362ull, out) == MT_OK && !memcmp(out, cfid, 8));
    memcpy(bad, root, 65);
    bad[0] = 0x02;
    CHECK(mt_fabric_compress_id(bad, 1, out) == MT_ERR_INVALID);

    static const struct { uint8_t epoch[16], op[16]; } ipk[] = {
        { { 0 }, { 0xc5, 0xf2, 0x69, 0x01, 0x87, 0x11, 0x51, 0x50, 0xc3, 0x56, 0xad, 0x93, 0xb3, 0x85, 0xbb, 0x0f } },
        { { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
          { 0xae, 0xd9, 0x56, 0x95, 0xf3, 0x75, 0xd2, 0xce, 0x78, 0x55, 0x6a, 0x41, 0x73, 0x0c, 0x3f, 0x43 } },
        { { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f },
          { 0x35, 0xca, 0x34, 0x6e, 0x5e, 0x24, 0xbb, 0xbe, 0x88, 0x9c, 0xf4, 0xd3, 0x5c, 0x5e, 0x82, 0x0a } },
        { { 0x23, 0x5b, 0xf7, 0xe6, 0x28, 0x23, 0xd3, 0x58, 0xdc, 0xa4, 0xba, 0x50, 0xb1, 0x53, 0x5f, 0x4b },
          { 0xa6, 0xf5, 0x30, 0x6b, 0xaf, 0x6d, 0x05, 0x0a, 0xf2, 0x3b, 0xa4, 0xbd, 0x6b, 0x9d, 0xd9, 0x60 } },
    };
    for (size_t i = 0; i < sizeof ipk / sizeof ipk[0]; i++) {
        uint8_t op[16];
        CHECK(mt_fabric_derive_ipk(ipk[i].epoch, cfid, op) == MT_OK && !memcmp(op, ipk[i].op, 16));
    }

    /* destination ID: Root01 / FAB...1D / Node01_01, epoch 10..1f, random i*7+3 (Python reference) */
    static const uint8_t r01_cfid[8] = { 0x38, 0x93, 0xc4, 0x32, 0x45, 0x26, 0xc7, 0x75 };
    static const uint8_t r01_ipk[16] = { 0x82, 0x0c, 0x5e, 0x7a, 0x91, 0xcb, 0xc8, 0xe1, 0xac, 0x22, 0xe4, 0x61, 0x6a, 0xfa, 0x3a, 0xc2 };
    static const uint8_t r01_dest[32] = { 0xca, 0x64, 0x1e, 0x69, 0x05, 0xe1, 0x6f, 0x23, 0x1e, 0xd7, 0x2e, 0x30, 0xc3, 0x67, 0x65, 0xd5,
                                          0x38, 0x23, 0x33, 0xf8, 0x5f, 0x65, 0x15, 0x23, 0x1d, 0x8e, 0x0b, 0xf3, 0x82, 0x95, 0xd0, 0x75 };
    uint8_t c[8], k[16], rnd[32], d[32];
    CHECK(mt_fabric_compress_id(pubof("Root01"), 0xfab000000000001dull, c) == MT_OK && !memcmp(c, r01_cfid, 8));
    CHECK(mt_fabric_derive_ipk(EPOCH, c, k) == MT_OK && !memcmp(k, r01_ipk, 16));
    for (int i = 0; i < 32; i++) rnd[i] = (uint8_t)(i * 7 + 3);
    CHECK(mt_fabric_destination_id(k, rnd, pubof("Root01"), 0xfab000000000001dull, 0xdededede00010001ull, d) == MT_OK);
    CHECK(!memcmp(d, r01_dest, 32));
}

/* ---- ACL entries ---- */

static void test_acl(void)
{
    uint8_t buf[128];
    mt_tlv_wr w;
    mt_span enc;
    mt_acl_entry e = { MT_ACL_PRIV_ADMINISTER, MT_ACL_AUTH_CASE, 1, 0, { 0x1122334455667788ull }, { { 0 } } };
    static const uint8_t want[] = { 0x15, 0x24, 0x01, 0x05, 0x24, 0x02, 0x02, 0x36, 0x03, 0x07, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
                                    0x18, 0x34, 0x04, 0x18 };
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    CHECK(mt_acl_entry_encode(&w, mt_tlv_anon(), &e) == MT_OK && mt_tlv_wr_done(&w, &enc) == MT_OK);
    CHECK(enc.len == sizeof want && !memcmp(enc.p, want, sizeof want));

    /* decode that, with the fabric index tag (254) a controller adds, and an unknown tag */
    static const uint8_t wire[] = { 0x15, 0x24, 0x01, 0x05, 0x24, 0x02, 0x02, 0x36, 0x03, 0x07, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
                                    0x18, 0x34, 0x04, 0x24, 0x09, 0x01, 0x24, 0xFE, 0x03, 0x18 };
    mt_tlv_rd r;
    mt_acl_entry d;
    mt_tlv_rd_init(&r, mt_span_of(wire, sizeof wire));
    CHECK(mt_tlv_next(&r) == MT_OK && mt_acl_entry_decode(&r, &d) == MT_OK && acl_eq(&d, &e));

    /* full entry with targets, round trip, then every proper truncation fails */
    mt_acl_entry f = { MT_ACL_PRIV_OPERATE, MT_ACL_AUTH_CASE, 4, 3, { 5, 0x1000, 0xFFFFFFFD00010001ull, MT_CERT_NODE_ID_MAX },
                       { { 0x201, 0x1, MT_ACL_NO_DEVTYPE }, { MT_ACL_NO_CLUSTER, MT_ACL_NO_ENDPOINT, 0x301 }, { 0x6, MT_ACL_NO_ENDPOINT, MT_ACL_NO_DEVTYPE } } };
    uint8_t big[160];
    mt_tlv_wr_init(&w, mt_buf_of(big, sizeof big));
    CHECK(mt_acl_entry_encode(&w, mt_tlv_anon(), &f) == MT_OK && mt_tlv_wr_done(&w, &enc) == MT_OK);
    mt_tlv_rd_init(&r, enc);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_acl_entry_decode(&r, &d) == MT_OK && acl_eq(&d, &f));
    int accepted = 0;
    for (size_t n = 0; n < enc.len; n++) {
        mt_tlv_rd_init(&r, mt_span_of(enc.p, n));
        if (mt_tlv_next(&r) == MT_OK && mt_acl_entry_decode(&r, &d) == MT_OK) accepted++;
    }
    CHECK(accepted == 0);
    mt_tlv_wr_init(&w, mt_buf_of(buf, 10));
    CHECK(mt_acl_entry_encode(&w, mt_tlv_anon(), &f) == MT_ERR_BUFFER_TOO_SMALL);

    /* five subjects exceed the cap */
    static const uint8_t five[] = { 0x15, 0x24, 0x01, 0x03, 0x24, 0x02, 0x02, 0x36, 0x03, 0x04, 1, 0x04, 2, 0x04, 3, 0x04, 4, 0x04, 5, 0x18, 0x34, 0x04, 0x18 };
    mt_tlv_rd_init(&r, mt_span_of(five, sizeof five));
    CHECK(mt_tlv_next(&r) == MT_OK && mt_acl_entry_decode(&r, &d) == MT_ERR_BUFFER_TOO_SMALL);
    /* missing privilege */
    static const uint8_t nopriv[] = { 0x15, 0x24, 0x02, 0x02, 0x18 };
    mt_tlv_rd_init(&r, mt_span_of(nopriv, sizeof nopriv));
    CHECK(mt_tlv_next(&r) == MT_OK && mt_acl_entry_decode(&r, &d) == MT_ERR_INVALID);

    /* validity */
    CHECK(mt_acl_entry_valid(&e) && mt_acl_entry_valid(&f));
    mt_acl_entry x = e;
    x.privilege = 0; CHECK(!mt_acl_entry_valid(&x));
    x = e; x.privilege = 6; CHECK(!mt_acl_entry_valid(&x));
    x = e; x.auth_mode = MT_ACL_AUTH_PASE; CHECK(!mt_acl_entry_valid(&x));
    x = e; x.auth_mode = 4; CHECK(!mt_acl_entry_valid(&x));
    x = e; x.auth_mode = MT_ACL_AUTH_GROUP; x.subjects[0] = 0xFFFFFFFFFFFF0005ull; CHECK(!mt_acl_entry_valid(&x));   /* group + administer */
    x.privilege = MT_ACL_PRIV_OPERATE; CHECK(mt_acl_entry_valid(&x));
    x.subjects[0] = 5; CHECK(!mt_acl_entry_valid(&x));                                                               /* not a group ID */
    x = e; x.subjects[0] = 0; CHECK(!mt_acl_entry_valid(&x));
    x = e; x.subjects[0] = 0xFFFFFFFFFFFFFFFFull; CHECK(!mt_acl_entry_valid(&x));
    x = e; x.subjects[0] = 0xFFFFFFFD00010000ull; CHECK(!mt_acl_entry_valid(&x));                                    /* CAT version 0 */
    x = e; x.n_targets = 1; x.targets[0] = (mt_acl_target){ MT_ACL_NO_CLUSTER, MT_ACL_NO_ENDPOINT, MT_ACL_NO_DEVTYPE }; CHECK(!mt_acl_entry_valid(&x)); /* empty target */
    x.targets[0] = (mt_acl_target){ MT_ACL_NO_CLUSTER, 1, 0x301 }; CHECK(!mt_acl_entry_valid(&x));                   /* endpoint and device type */
    x = e; x.n_subjects = 5; CHECK(!mt_acl_entry_valid(&x));
}

/* ---- commissioning flow ---- */

static void test_flow(void)
{
    uint8_t idx = 0, priv[32], rnd[32], dest[32];
    const mt_fabric *f;
    mt_span c;
    uint8_t cbuf[MT_FABRIC_CERT_MAX];
    fresh();
    CHECK(mt_fabric_load(&T, scratch()) == MT_OK && mt_fabric_count(&T) == 0);
    for (int i = 0; i < 32; i++) rnd[i] = (uint8_t)(i * 7 + 3);

    /* wrong order */
    CHECK(mt_fabric_stage_rcac(&T, tl("Root01")) == MT_OK);
    CHECK(mt_fabric_add_noc(&T, tl("Node01_01"), tl("ICA01"), EPOCH, ADMIN, 1, NOW, scratch(), &idx) == MT_ERR_STATE);   /* no key */
    CHECK(mt_fabric_stage_rcac(&T, tl("Root01")) == MT_ERR_STATE);                                                         /* once only */
    mt_fabric_abort(&T);
    CHECK(mt_fabric_pending_kind(&T) == MT_FABRIC_PEND_NONE && T.pend.rcac_len == 0);
    memset(priv, 0x21, 32);
    CHECK(mt_fabric_stage_key(&T, priv, pubof("Node01_01")) == MT_OK);
    CHECK(mt_fabric_add_noc(&T, tl("Node01_01"), tl("ICA01"), EPOCH, ADMIN, 1, NOW, scratch(), &idx) == MT_ERR_STATE);    /* no root */
    CHECK(mt_fabric_stage_rcac(&T, tl("ICA01")) == MT_ERR_INVALID);                                                        /* not a root */
    CHECK(mt_fabric_stage_rcac(&T, tl("Node01_01")) == MT_ERR_INVALID);

    /* rejected adds leave nothing pending */
    CHECK(stage_all("Root02", "Node01_01", "ICA01", NOW, 0x21, &idx) == MT_ERR_INVALID);   /* wrong root */
    CHECK(stage_all("Root01", "Node01_01", "ICA01", 1000, 0x21, &idx) == MT_ERR_EXPIRED);
    CHECK(stage_all("Root01", "Node01_01", NULL, NOW, 0x21, &idx) != MT_OK);               /* ICAC missing */
    CHECK(mt_fabric_stage_key(&T, priv, pubof("Node01_02")) == MT_OK);
    CHECK(T.pend.rcac_len > 0);                       /* the failed attempts above keep the root staged */
    CHECK(mt_fabric_add_noc(&T, tl("Node01_01"), tl("ICA01"), EPOCH, ADMIN, 1, NOW, scratch(), &idx) == MT_ERR_INVALID);  /* not the staged key */
    CHECK(mt_fabric_pending_kind(&T) == MT_FABRIC_PEND_NONE && mt_fabric_count(&T) == 0);
    /* chain-only check for the NOCResponse classification: the staged root */
    CHECK(mt_fabric_check_chain(&T, 0, tl("Node01_01"), tl("ICA01"), scratch()) == MT_OK);
    CHECK(mt_fabric_check_chain(&T, 0, tl("Node01_01"), mt_span_of(NULL, 0), scratch()) != MT_OK);
    CHECK(mt_fabric_check_chain(&T, 0, tl("Node02_01"), tl("ICA02"), scratch()) != MT_OK);
    CHECK(mt_fabric_check_chain(&T, 1, tl("Node01_01"), tl("ICA01"), scratch()) == MT_ERR_STATE); /* root staged */

    /* AddNOC: pending fabric visible, nothing stored */
    CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x21, &idx) == MT_OK);
    CHECK(idx == 1);
    CHECK(mt_fabric_pending_kind(&T) == MT_FABRIC_PEND_NEW && mt_fabric_count(&T) == 1 && mt_fabric_committed_count(&T) == 0);
    f = mt_fabric_get(&T, 1);
    CHECK(f && f->pending && f == mt_fabric_pending(&T) && f == mt_fabric_nth(&T, 0));
    CHECK(f->fabric_id == 0xfab000000000001dull && f->node_id == 0xdededede00010001ull && f->vendor_id == 0xFFF1);
    CHECK(f->n_acl == 1 && f->acl[0].privilege == MT_ACL_PRIV_ADMINISTER && f->acl[0].auth_mode == MT_ACL_AUTH_CASE &&
          f->acl[0].n_subjects == 1 && f->acl[0].subjects[0] == ADMIN && f->acl[0].n_targets == 0);
    CHECK(!memcmp(f->root_pub, pubof("Root01"), 65));
    CHECK(nkeys(&K) == 0);
    CHECK(mt_fabric_stage_key(&T, priv, pubof("Node01_01")) == MT_ERR_STATE);               /* after AddNOC */
    CHECK(mt_fabric_add_noc(&T, tl("Node01_01"), tl("ICA01"), EPOCH, ADMIN, 1, NOW, scratch(), &idx) == MT_ERR_STATE);
    /* CASE sees the pending fabric */
    CHECK(mt_fabric_destination_id(f->ipk, rnd, f->root_pub, f->fabric_id, f->node_id, dest) == MT_OK);
    const mt_fabric *m = NULL;
    CHECK(mt_fabric_match_destination(&T, rnd, dest, &m) == MT_OK && m == f);
    dest[5] ^= 1;
    CHECK(mt_fabric_match_destination(&T, rnd, dest, &m) == MT_ERR_NOT_FOUND);
    CHECK(mt_fabric_read_cert(&T, f, MT_FKIND_NOC, mt_buf_of(NULL, 0), &c) == MT_OK && c.len == vec("Node01_01")->tlv_len && !memcmp(c.p, vec("Node01_01")->tlv, c.len));
    CHECK(mt_fabric_read_cert(&T, f, MT_FKIND_ICAC, mt_buf_of(NULL, 0), &c) == MT_OK && c.len == vec("ICA01")->tlv_len);
    CHECK(mt_fabric_read_cert(&T, f, MT_FKIND_RCAC, mt_buf_of(NULL, 0), &c) == MT_OK && c.len == vec("Root01")->tlv_len);
    uint8_t key[32];
    CHECK(mt_fabric_read_opkey(&T, f, key) == MT_OK && !memcmp(key, priv, 0) && key[0] == 0x21);

    /* abort drops it everywhere and wipes the staged key */
    mt_fabric_abort(&T);
    CHECK(mt_fabric_count(&T) == 0 && mt_fabric_get(&T, 1) == NULL && nkeys(&K) == 0);
    CHECK(mt_fabric_match_destination(&T, rnd, dest, &m) == MT_ERR_NOT_FOUND);
    CHECK(!T.pend.has_key && T.pend.priv[0] == 0 && T.pend.fab.index == 0);
    CHECK(mt_fabric_commit(&T, scratch()) == MT_ERR_STATE);

    /* commit */
    CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x21, &idx) == MT_OK && idx == 2);   /* the cursor moved on */
    mt_fabric_abort(&T);
    CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x21, &idx) == MT_OK && idx == 3);
    mt_fabric_abort(&T);
    T.next_index = 0;
    CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x21, &idx) == MT_OK && idx == 1);
    CHECK(mt_fabric_commit(&T, scratch()) == MT_OK);
    CHECK(mt_fabric_pending_kind(&T) == MT_FABRIC_PEND_NONE && mt_fabric_committed_count(&T) == 1 && T.pend.priv[0] == 0);
    for (int kd = MT_FKIND_RCAC; kd <= MT_FKIND_ACL; kd++) CHECK(has(&K, 1, kd));
    CHECK(nkeys(&K) == 5 && K.applies == 1);
    f = mt_fabric_get(&T, 1);
    CHECK(f && !f->pending);
    CHECK(mt_fabric_read_cert(&T, f, MT_FKIND_NOC, mt_buf_of(cbuf, sizeof cbuf), &c) == MT_OK && c.len == vec("Node01_01")->tlv_len && !memcmp(c.p, vec("Node01_01")->tlv, c.len));
    CHECK(mt_fabric_read_cert(&T, f, MT_FKIND_ICAC, mt_buf_of(cbuf, sizeof cbuf), &c) == MT_OK && c.len == vec("ICA01")->tlv_len);
    CHECK(mt_fabric_read_cert(&T, f, MT_FKIND_RCAC, mt_buf_of(cbuf, sizeof cbuf), &c) == MT_OK && !memcmp(c.p, vec("Root01")->tlv, c.len));
    CHECK(mt_fabric_read_cert(&T, f, MT_FKIND_NOC, mt_buf_of(cbuf, 10), &c) == MT_ERR_BUFFER_TOO_SMALL);
    CHECK(mt_fabric_read_opkey(&T, f, key) == MT_OK && key[0] == 0x21 && key[31] == 0x21);
    CHECK(mt_fabric_match_destination(&T, rnd, (mt_fabric_destination_id(f->ipk, rnd, f->root_pub, f->fabric_id, f->node_id, dest), dest), &m) == MT_OK && m == f);
    check_reload();

    /* same root key and fabric ID again: conflict, with or without the ICAC */
    CHECK(mt_fabric_conflict(&T, pubof("Root01"), 0xfab000000000001dull) && !mt_fabric_conflict(&T, pubof("Root02"), 0xfab000000000001dull));
    CHECK(stage_all("Root01", "Node01_02", NULL, NOW, 0x22, &idx) == MT_ERR_INVALID);
    mt_fabric_abort(&T);

    /* second fabric under another root, ICAC-based */
    CHECK(stage_all("Root02", "Node02_01", "ICA02", 0, 0x23, &idx) == MT_OK && idx == 2);
    CHECK(mt_fabric_count(&T) == 2 && mt_fabric_committed_count(&T) == 1 && mt_fabric_nth(&T, 1)->pending);
    CHECK(mt_fabric_commit(&T, scratch()) == MT_OK);
    CHECK(mt_fabric_committed_count(&T) == 2 && nkeys(&K) == 10);
    CHECK(memcmp(mt_fabric_get(&T, 1)->cfid, mt_fabric_get(&T, 2)->cfid, 8) != 0);
    check_reload();
}

/* ---- UpdateNOC ---- */

static void test_update(void)
{
    uint8_t idx, rnd[32], dest[32], priv[32], cbuf[MT_FABRIC_CERT_MAX];
    const mt_fabric *f;
    const mt_fabric *m;
    mt_span c;
    fresh();
    CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x31, &idx) == MT_OK && mt_fabric_commit(&T, scratch()) == MT_OK);
    mt_acl_entry extra = { MT_ACL_PRIV_VIEW, MT_ACL_AUTH_CASE, 0, 0, { 0 }, { { 0 } } };
    mt_acl_entry two[2] = { T.slots[0].acl[0], extra };
    CHECK(mt_fabric_acl_set(&T, 1, two, 2, scratch()) == MT_OK);
    for (int i = 0; i < 32; i++) rnd[i] = (uint8_t)(i + 1);

    memset(priv, 0x32, 32);
    CHECK(mt_fabric_update_noc(&T, 1, tl("Node01_02"), mt_span_of(NULL, 0), NOW, scratch()) == MT_ERR_STATE);   /* no key */
    CHECK(mt_fabric_stage_key(&T, priv, pubof("Node01_02")) == MT_OK);
    CHECK(mt_fabric_update_noc(&T, 9, tl("Node01_02"), mt_span_of(NULL, 0), NOW, scratch()) == MT_ERR_NOT_FOUND);
    CHECK(mt_fabric_update_noc(&T, 1, tl("Node01_01"), tl("ICA01"), NOW, scratch()) == MT_ERR_INVALID);          /* not the staged key */
    CHECK(mt_fabric_update_noc(&T, 1, tl("Node01_02"), mt_span_of(NULL, 0), 1000, scratch()) == MT_ERR_EXPIRED);
    CHECK(mt_fabric_pending_kind(&T) == MT_FABRIC_PEND_NONE);
    CHECK(mt_fabric_stage_key(&T, priv, pubof("Node02_01")) == MT_OK);
    CHECK(mt_fabric_update_noc(&T, 1, tl("Node02_01"), tl("ICA02"), NOW, scratch()) == MT_ERR_INVALID);           /* another root */
    CHECK(mt_fabric_pending_kind(&T) == MT_FABRIC_PEND_NONE);
    /* chain-only check against fabric 1's stored root; leaves nothing staged */
    CHECK(mt_fabric_check_chain(&T, 1, tl("Node01_01"), tl("ICA01"), scratch()) == MT_OK);
    CHECK(mt_fabric_check_chain(&T, 1, tl("Node02_01"), tl("ICA02"), scratch()) != MT_OK);
    CHECK(mt_fabric_check_chain(&T, 9, tl("Node01_01"), tl("ICA01"), scratch()) == MT_ERR_NOT_FOUND);
    CHECK(T.pend.rcac_len == 0 && mt_fabric_check_chain(&T, 0, tl("Node01_01"), tl("ICA01"), scratch()) == MT_ERR_STATE);
    mt_fabric_abort(&T);

    CHECK(mt_fabric_stage_key(&T, priv, pubof("Node01_02")) == MT_OK);
    CHECK(mt_fabric_update_noc(&T, 1, tl("Node01_02"), mt_span_of(NULL, 0), NOW, scratch()) == MT_OK);
    CHECK(mt_fabric_pending_kind(&T) == MT_FABRIC_PEND_UPDATE && mt_fabric_count(&T) == 1 && mt_fabric_committed_count(&T) == 1);
    f = mt_fabric_get(&T, 1);
    CHECK(f == mt_fabric_pending(&T) && f->pending && f->node_id == 0xdededede00010002ull && f->n_acl == 2);
    CHECK(T.slots[0].node_id == 0xdededede00010001ull);       /* committed copy untouched */
    CHECK(mt_fabric_destination_id(f->ipk, rnd, f->root_pub, f->fabric_id, f->node_id, dest) == MT_OK);
    CHECK(mt_fabric_match_destination(&T, rnd, dest, &m) == MT_OK && m == f);
    CHECK(mt_fabric_destination_id(f->ipk, rnd, f->root_pub, f->fabric_id, 0xdededede00010001ull, dest) == MT_OK);
    CHECK(mt_fabric_match_destination(&T, rnd, dest, &m) == MT_ERR_NOT_FOUND);    /* the old node ID no longer matches */
    CHECK(mt_fabric_read_cert(&T, f, MT_FKIND_RCAC, mt_buf_of(NULL, 0), &c) == MT_OK && c.len == vec("Root01")->tlv_len);
    CHECK(mt_fabric_read_cert(&T, f, MT_FKIND_ICAC, mt_buf_of(NULL, 0), &c) == MT_ERR_NOT_FOUND);

    /* abort keeps the old credentials, fully */
    mt_fabric_abort(&T);
    CHECK(mt_fabric_get(&T, 1)->node_id == 0xdededede00010001ull && !mt_fabric_get(&T, 1)->pending);
    CHECK(mt_fabric_read_cert(&T, mt_fabric_get(&T, 1), MT_FKIND_ICAC, mt_buf_of(cbuf, sizeof cbuf), &c) == MT_OK);

    /* commit */
    CHECK(mt_fabric_stage_key(&T, priv, pubof("Node01_02")) == MT_OK);
    CHECK(mt_fabric_update_noc(&T, 1, tl("Node01_02"), mt_span_of(NULL, 0), NOW, scratch()) == MT_OK);
    CHECK(mt_fabric_commit(&T, scratch()) == MT_OK);
    f = mt_fabric_get(&T, 1);
    CHECK(f && !f->pending && f->node_id == 0xdededede00010002ull && f->n_acl == 2 && mt_fabric_pending_kind(&T) == MT_FABRIC_PEND_NONE);
    CHECK(!has(&K, 1, MT_FKIND_ICAC) && has(&K, 1, MT_FKIND_NOC) && nkeys(&K) == 4);
    CHECK(mt_fabric_read_cert(&T, f, MT_FKIND_NOC, mt_buf_of(cbuf, sizeof cbuf), &c) == MT_OK && c.len == vec("Node01_02")->tlv_len);
    uint8_t key[32];
    CHECK(mt_fabric_read_opkey(&T, f, key) == MT_OK && key[0] == 0x32);
    check_reload();

    /* an ACL edit during a pending update lands in both copies and in storage */
    CHECK(mt_fabric_stage_key(&T, priv, pubof("Node01_01")) == MT_OK);
    CHECK(mt_fabric_update_noc(&T, 1, tl("Node01_01"), tl("ICA01"), NOW, scratch()) == MT_OK);
    mt_acl_entry one[1] = { two[0] };
    CHECK(mt_fabric_acl_set(&T, 1, one, 1, scratch()) == MT_OK);
    CHECK(mt_fabric_get(&T, 1)->n_acl == 1 && T.slots[0].n_acl == 1);
    CHECK(mt_fabric_commit(&T, scratch()) == MT_OK);
    CHECK(has(&K, 1, MT_FKIND_ICAC));
    check_reload();
}

/* ---- remove, ACL, label ---- */

static void test_modify(void)
{
    uint8_t idx;
    fresh();
    CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x41, &idx) == MT_OK && mt_fabric_commit(&T, scratch()) == MT_OK);
    CHECK(stage_all("Root02", "Node02_01", "ICA02", NOW, 0x42, &idx) == MT_OK && idx == 2 && mt_fabric_commit(&T, scratch()) == MT_OK);

    /* labels */
    CHECK(mt_fabric_set_label(&T, 1, "Apple Home", 10, scratch()) == MT_OK && !strcmp(mt_fabric_get(&T, 1)->label, "Apple Home"));
    CHECK(mt_fabric_set_label(&T, 2, "Apple Home", 10, scratch()) == MT_ERR_INVALID);
    CHECK(mt_fabric_label_in_use(&T, "Apple Home", 10, 2) && !mt_fabric_label_in_use(&T, "Apple Home", 10, 1));
    CHECK(mt_fabric_set_label(&T, 1, "Apple Home", 10, scratch()) == MT_OK);       /* own label again */
    CHECK(mt_fabric_set_label(&T, 2, "Ho\0me", 5, scratch()) == MT_ERR_INVALID);  /* embedded NUL */
    CHECK(!mt_fabric_label_in_use(&T, "", 0, 2) && mt_fabric_set_label(&T, 2, "", 0, scratch()) == MT_OK); /* empty: never in use */
    CHECK(mt_fabric_set_label(&T, 1, "", 0, scratch()) == MT_OK && mt_fabric_set_label(&T, 1, "Apple Home", 10, scratch()) == MT_OK);
    CHECK(mt_fabric_set_label(&T, 2, "0123456789012345678901234567890123", 34, scratch()) == MT_ERR_INVALID);
    CHECK(mt_fabric_set_label(&T, 2, "01234567890123456789012345678901", 32, scratch()) == MT_OK);
    CHECK(mt_fabric_set_label(&T, 2, "", 0, scratch()) == MT_OK && !mt_fabric_get(&T, 2)->label[0]);
    CHECK(mt_fabric_set_label(&T, 7, "x", 1, scratch()) == MT_ERR_NOT_FOUND);
    check_reload();

    /* ACL */
    mt_acl_entry e[5];
    memset(e, 0, sizeof e);
    for (int i = 0; i < 5; i++) { e[i].privilege = MT_ACL_PRIV_OPERATE; e[i].auth_mode = MT_ACL_AUTH_CASE; e[i].n_subjects = 1; e[i].subjects[0] = 100 + (unsigned)i; }
    e[1].n_targets = 3;
    e[1].targets[0] = (mt_acl_target){ 0x201, 1, MT_ACL_NO_DEVTYPE };
    e[1].targets[1] = (mt_acl_target){ MT_ACL_NO_CLUSTER, MT_ACL_NO_ENDPOINT, 0x301 };
    e[1].targets[2] = (mt_acl_target){ 0x6, MT_ACL_NO_ENDPOINT, MT_ACL_NO_DEVTYPE };
    e[1].n_subjects = 4; e[1].subjects[1] = 7; e[1].subjects[2] = 0xFFFFFFFD00020003ull; e[1].subjects[3] = 9;
    unsigned applies = (unsigned)K.applies;
    CHECK(mt_fabric_acl_set(&T, 1, e, 5, scratch()) == MT_ERR_BUFFER_TOO_SMALL);
    mt_acl_entry bad[2] = { e[0], e[0] };
    bad[1].privilege = 9;
    CHECK(mt_fabric_acl_set(&T, 1, bad, 2, scratch()) == MT_ERR_INVALID);
    CHECK((unsigned)K.applies == applies);                      /* nothing written */
    CHECK(mt_fabric_acl_set(&T, 1, e, 4, scratch()) == MT_OK && mt_fabric_get(&T, 1)->n_acl == 4);
    CHECK(mt_fabric_acl_set(&T, 3, e, 1, scratch()) == MT_ERR_NOT_FOUND);
    check_reload();
    CHECK(mt_fabric_acl_set(&T, 1, e, 0, scratch()) == MT_OK && mt_fabric_get(&T, 1)->n_acl == 0);   /* empty is allowed at this layer */
    check_reload();
    CHECK(mt_fabric_acl_set(&T, 1, e, 1, mt_buf_of(scratch_mem, 100)) == MT_ERR_BUFFER_TOO_SMALL);

    /* ACL/label edits of a pending-new fabric stay in RAM until commit */
    CHECK(stage_all("Root03", "Node01_02", NULL, 0, 0x43, &idx) != MT_OK);    /* Root03 is not Node01_02's issuer */
    mt_fabric_abort(&T);
    mt_fabric_remove(&T, 2);
    CHECK(stage_all("Root02", "Node02_02", "ICA02", NOW, 0x44, &idx) == MT_OK && idx == 3);
    unsigned keys = nkeys(&K);
    CHECK(mt_fabric_set_label(&T, 3, "Pending", 7, scratch()) == MT_OK && mt_fabric_acl_set(&T, 3, e, 2, scratch()) == MT_OK);
    CHECK(nkeys(&K) == keys && !strcmp(mt_fabric_get(&T, 3)->label, "Pending") && mt_fabric_get(&T, 3)->n_acl == 2);
    CHECK(mt_fabric_commit(&T, scratch()) == MT_OK);
    check_reload();

    /* remove */
    CHECK(mt_fabric_remove(&T, 9) == MT_ERR_NOT_FOUND);
    CHECK(mt_fabric_remove(&T, 1) == MT_OK);
    CHECK(mt_fabric_get(&T, 1) == NULL && mt_fabric_committed_count(&T) == 1 && !has(&K, 1, MT_FKIND_META) && nkeys(&K) == 5);
    check_reload();
    CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x45, &idx) == MT_OK && idx == 4);   /* cursor, not the lowest free */
    CHECK(mt_fabric_remove(&T, 4) == MT_OK && mt_fabric_pending_kind(&T) == MT_FABRIC_PEND_NONE);   /* the pending one */
    CHECK(mt_fabric_remove(&T, 3) == MT_OK && mt_fabric_count(&T) == 0 && nkeys(&K) == 0);
    mt_fabric_abort(&T);
    /* the cursor wraps and skips used indices */
    T.next_index = 253;
    CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x46, &idx) == MT_OK && idx == 254 && mt_fabric_commit(&T, scratch()) == MT_OK);
    CHECK(stage_all("Root02", "Node02_01", "ICA02", NOW, 0x46, &idx) == MT_OK && idx == 1);
    mt_fabric_abort(&T);
    check_reload();
}

/* ---- full table (synthetic images written in the documented layout) ---- */

static void put_synth(unsigned idx, uint64_t fid, uint8_t seed)
{
    uint8_t buf[256], root[65], key[32], ep[16];
    mt_tlv_wr w;
    mt_span enc;
    memset(root, seed, sizeof root); root[0] = 4;
    memset(key, seed, 32); memset(ep, seed, 16);
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_STRUCT);
    mt_tlv_put_u(&w, mt_tlv_ctx(0), 1); mt_tlv_put_u(&w, mt_tlv_ctx(1), fid); mt_tlv_put_u(&w, mt_tlv_ctx(2), 0x55);
    mt_tlv_put_u(&w, mt_tlv_ctx(3), 0x1234); mt_tlv_put_utf8(&w, mt_tlv_ctx(4), "synth", 5);
    mt_tlv_put_bytes(&w, mt_tlv_ctx(5), mt_span_of(key, 32)); mt_tlv_put_bytes(&w, mt_tlv_ctx(6), mt_span_of(ep, 16));
    mt_tlv_put_bytes(&w, mt_tlv_ctx(7), mt_span_of(root, 65));
    mt_tlv_end(&w);
    mt_tlv_wr_done(&w, &enc);
    f_set(&K, MT_FKEY(idx, MT_FKIND_META), enc);
    static const uint8_t acl[] = { 0x16, 0x15, 0x24, 0x01, 0x05, 0x24, 0x02, 0x02, 0x34, 0x03, 0x34, 0x04, 0x18, 0x18 };
    f_set(&K, MT_FKEY(idx, MT_FKIND_ACL), mt_span_of(acl, sizeof acl));
    f_finish(&K, true);
}

static void test_full_and_load(void)
{
    uint8_t idx;
    fresh();
    put_synth(7, 0x77, 0x07);
    put_synth(9, 0x99, 0x09);
    put_synth(200, 0xC8, 0x0C);
    CHECK(mt_fabric_load(&T, scratch()) == MT_OK && T.skipped == 0 && mt_fabric_committed_count(&T) == 3);
    CHECK(mt_fabric_get(&T, 7) && mt_fabric_get(&T, 200) && mt_fabric_get(&T, 7)->fabric_id == 0x77 && !strcmp(mt_fabric_get(&T, 9)->label, "synth"));
    CHECK(mt_fabric_get(&T, 9)->n_acl == 1 && mt_fabric_get(&T, 9)->vendor_id == 0x1234 && T.next_index == 200);
    CHECK(mt_fabric_get(&T, 0) == NULL && mt_fabric_get(&T, 8) == NULL);
    CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x51, &idx) == MT_ERR_BUFFER_TOO_SMALL);
    CHECK(mt_fabric_remove(&T, 9) == MT_OK);
    CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x51, &idx) == MT_OK && idx == 201);
    CHECK(mt_fabric_commit(&T, scratch()) == MT_OK && mt_fabric_committed_count(&T) == 3);
    check_reload();

    /* a damaged image and a fourth one are skipped, the rest still loads */
    ent *m = kfind(K.applied, MT_FKEY(7, MT_FKIND_META));
    m->d[m->len - 3] ^= 0xFF;            /* inside the root key: still parses */
    m->len -= 2;                         /* truncated: no longer parses */
    put_synth(11, 0x11, 0x0B);
    mt_fabric_init(&T, &OPS);
    CHECK(mt_fabric_load(&T, scratch()) == MT_OK && T.skipped == 1 && mt_fabric_committed_count(&T) == 3 && !mt_fabric_get(&T, 7));
    put_synth(12, 0x12, 0x0C);
    mt_fabric_init(&T, &OPS);
    CHECK(mt_fabric_load(&T, scratch()) == MT_OK);
    CHECK(T.skipped == 2 && mt_fabric_committed_count(&T) == 3 && mt_fabric_get(&T, 200) && !mt_fabric_get(&T, 201));
    ent *a = kfind(K.applied, MT_FKEY(11, MT_FKIND_ACL));
    a->used = false;                     /* meta without ACL */
    mt_fabric_init(&T, &OPS);
    CHECK(mt_fabric_load(&T, scratch()) == MT_OK && !mt_fabric_get(&T, 11));
}

/* ---- storage failures ---- */

static void test_failures(void)
{
    uint8_t idx;
    const mt_fabric *f;
    fresh();
    /* every possible failing step of a commit leaves nothing applied and the pending fabric retryable */
    for (int step = 1; step <= 7; step++) {
        memset(&K, 0, sizeof K);
        OPS = ops_of(&K);
        mt_fabric_init(&T, &OPS);
        CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x61, &idx) == MT_OK);
        K.fail_in = step;                                   /* set x5 (meta, acl, 3 certs) then finish */
        mt_err e = mt_fabric_commit(&T, scratch());
        if (step <= 6) {
            CHECK(e == MT_ERR_IO && K.drops == 1 && K.applies == 0);
            CHECK(nkeys(&K) == 0 && mt_fabric_committed_count(&T) == 0);
            CHECK(mt_fabric_pending_kind(&T) == MT_FABRIC_PEND_NEW && mt_fabric_get(&T, idx)->pending);
            K.fail_in = 0;
            CHECK(mt_fabric_commit(&T, scratch()) == MT_OK && nkeys(&K) == 5);   /* retry works */
        } else {
            CHECK(e == MT_OK && nkeys(&K) == 5);                                 /* step 7 never triggers */
        }
        K.fail_in = 0;
        check_reload();
    }

    /* failed ACL/label/remove: RAM and storage unchanged */
    f = mt_fabric_get(&T, 1);
    mt_acl_entry e1 = f->acl[0];
    e1.subjects[0] = 77;
    for (int step = 1; step <= 6; step++) {
        K.fail_in = step;
        CHECK(mt_fabric_acl_set(&T, 1, &e1, 1, scratch()) == MT_ERR_IO);
        CHECK(mt_fabric_get(&T, 1)->acl[0].subjects[0] == ADMIN);
        K.fail_in = step;
        CHECK(mt_fabric_set_label(&T, 1, "abc", 3, scratch()) == MT_ERR_IO && !mt_fabric_get(&T, 1)->label[0]);
        K.fail_in = 0;
        check_reload();
    }
    for (int step = 1; step <= 6; step++) {
        K.fail_in = step;
        CHECK(mt_fabric_remove(&T, 1) == MT_ERR_IO && mt_fabric_get(&T, 1) != NULL);
        K.fail_in = 0;
        check_reload();
    }
    CHECK(mt_fabric_remove(&T, 1) == MT_OK && nkeys(&K) == 0);

    /* too small a scratch */
    CHECK(stage_all("Root01", "Node01_01", "ICA01", NOW, 0x62, &idx) == MT_OK);
    CHECK(mt_fabric_commit(&T, mt_buf_of(scratch_mem, 64)) == MT_ERR_BUFFER_TOO_SMALL);
    CHECK(nkeys(&K) == 0 && mt_fabric_pending_kind(&T) == MT_FABRIC_PEND_NEW);
    CHECK(mt_fabric_commit(&T, scratch()) == MT_OK);
}

int main(void)
{
    test_ids();
    test_acl();
    test_flow();
    test_update();
    test_modify();
    test_full_and_load();
    test_failures();
    printf("matter-fabric: %d checks, %d failures; sizeof(table)=%zu fabric=%zu acl_entry=%zu\n", checks, failures,
           sizeof(mt_fabric_table), sizeof(mt_fabric), sizeof(mt_acl_entry));
    return failures ? 1 : 0;
}
