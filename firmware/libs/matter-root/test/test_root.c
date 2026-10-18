/* Host tests for matter-root: Basic Information here, the commissioning clusters in test_comm.c.
 * The cluster runs inside a real matter-dm tree and is read
 * and written through the mt_im_dm boundary (attr_at / read / write), as the IM engine does.
 * Expected values: attribute ids, types, access and quality flags and the cluster revision are taken from
 * the Matter 1.3.0.0 cluster IDL (BasicInformation = 40, revision 3); the values come from the test config. */
#include <stdio.h>
#include <string.h>
#include "mt_root.h"

int g_fail, g_checks; /* shared with test_comm.c */
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

/* ---- RAM kv fake with the staged/applied contract of mt_kv_ops ---- */
#define KV_N 4
typedef struct {
    struct { uint16_t key; uint8_t v[96]; size_t n; bool used; } applied[KV_N], staged[KV_N];
    bool fail_set, fail_finish;
    int finishes;
} kv_fake;

static mt_err kv_get(void *c, uint16_t key, mt_buf out, size_t *len)
{
    kv_fake *k = c;
    for (int i = 0; i < KV_N; i++)
        if (k->applied[i].used && k->applied[i].key == key) {
            if (k->applied[i].n > out.cap) return MT_ERR_BUFFER_TOO_SMALL;
            memcpy(out.p, k->applied[i].v, k->applied[i].n);
            *len = k->applied[i].n;
            return MT_OK;
        }
    return MT_ERR_NOT_FOUND;
}
static mt_err kv_set(void *c, uint16_t key, mt_span val)
{
    kv_fake *k = c;
    if (k->fail_set || val.len > 96) return MT_ERR_IO;
    for (int i = 0; i < KV_N; i++)
        if (!k->staged[i].used || k->staged[i].key == key) {
            k->staged[i].used = true;
            k->staged[i].key = key;
            memcpy(k->staged[i].v, val.p, val.len);
            k->staged[i].n = val.len;
            return MT_OK;
        }
    return MT_ERR_IO;
}
static mt_err kv_del(void *c, uint16_t key) { (void)c; (void)key; return MT_OK; }
static mt_err kv_finish(void *c, bool apply)
{
    kv_fake *k = c;
    k->finishes++;
    if (apply && k->fail_finish) apply = false;
    if (apply)
        for (int i = 0; i < KV_N; i++)
            if (k->staged[i].used) {
                int j = 0;
                while (j < KV_N - 1 && k->applied[j].used && k->applied[j].key != k->staged[i].key) j++;
                k->applied[j] = k->staged[i];
            }
    memset(k->staged, 0, sizeof k->staged);
    return apply ? MT_OK : MT_ERR_IO;
}
static mt_kv_ops kv_ops(kv_fake *k) { mt_kv_ops o = { k, kv_get, kv_set, kv_del, kv_finish }; return o; }

/* ---- fixture ---- */
static const mt_basic_cfg CFG = {
    "Test Vendor", 0xFFF1, "Test Thermostat", 0x8000, 7, "hw-7", 0x00010203, "1.2.3", "SN-0001", "uid-abc",
    3, 3, 1,
};
#define KEY 0x0001 /* MT_FKEY(0, 1): a node-level record */

typedef struct {
    mt_basic b;
    const mt_dm_cluster *cls[2];
    mt_dm_devtype types[1];
    mt_dm_endpoint ep;
    mt_dm_node node;
    mt_dm dm;
} fix;

static void fix_init(fix *f, const mt_kv_ops *kv)
{
    memset(f, 0, sizeof *f);
    CHECK(mt_basic_init(&f->b, &CFG, kv, KEY) == MT_OK);
    f->cls[0] = &mt_dm_descriptor;
    f->cls[1] = &f->b.cluster;
    f->types[0].type = 0x16;
    f->types[0].revision = 1;
    f->ep.id = 0;
    f->ep.n_types = 1;
    f->ep.n_clusters = 2;
    f->ep.types = f->types;
    f->ep.clusters = f->cls;
    f->node.eps = &f->ep;
    f->node.n_eps = 1;
    mt_dm_cfg c = { &f->node, NULL, NULL, NULL, 100 };
    CHECK(mt_dm_init(&f->dm, &c) == MT_OK);
}

static bool find_attr(fix *f, uint32_t id, mt_im_attr *a)
{
    for (uint16_t i = 0; !mt_dm_im.attr_at(&f->dm, i, a); i++)
        if (a->cluster == MT_BASIC_CLUSTER_ID && a->attr == id) return true;
    return false;
}

/* Reads attribute `id` (item 0) and leaves the encoded value in rd, positioned on it. */
static uint8_t g_buf[256];
static mt_err rd_attr(fix *f, uint32_t id, uint16_t item, mt_tlv_rd *rd)
{
    mt_im_attr a;
    mt_tlv_wr w;
    mt_im_rctx rc = { NULL, false };
    if (!find_attr(f, id, &a)) return MT_ERR_NOT_FOUND;
    mt_tlv_wr_init(&w, mt_buf_of(g_buf, sizeof g_buf));
    mt_err e = mt_dm_im.read(&f->dm, &rc, &a, item, &w, mt_tlv_anon());
    if (e) return e;
    mt_tlv_rd_init(rd, mt_tlv_wr_span(&w));
    return mt_tlv_next(rd);
}

static bool str_is(fix *f, uint32_t id, const char *want)
{
    mt_tlv_rd r;
    mt_span s;
    return rd_attr(f, id, 0, &r) == MT_OK && !mt_tlv_get_utf8(&r, &s) && s.len == strlen(want) &&
           !memcmp(s.p, want, s.len);
}
static bool uint_is(fix *f, uint32_t id, uint64_t want)
{
    mt_tlv_rd r;
    uint64_t v;
    return rd_attr(f, id, 0, &r) == MT_OK && !mt_tlv_get_u64(&r, &v) && v == want;
}

static mt_im_status wr_str(fix *f, uint32_t id, const char *s, size_t len)
{
    mt_im_attr a;
    uint8_t buf[64];
    mt_tlv_wr w;
    mt_tlv_rd r;
    mt_im_wctx wc = { NULL, false, false };
    if (!find_attr(f, id, &a)) return 0xFFFF;
    mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
    mt_tlv_put_utf8(&w, mt_tlv_anon(), s, len);
    mt_tlv_rd_init(&r, mt_tlv_wr_span(&w));
    mt_tlv_next(&r);
    return mt_dm_im.write(&f->dm, &wc, &a, MT_IM_WR_VALUE, &r);
}

/* ---- tests ---- */

static void test_values(void)
{
    kv_fake k = { 0 };
    mt_kv_ops ops = kv_ops(&k);
    fix f;
    fix_init(&f, &ops);
    CHECK(uint_is(&f, MT_BASIC_DATA_MODEL_REVISION, 17));
    CHECK(str_is(&f, MT_BASIC_VENDOR_NAME, "Test Vendor"));
    CHECK(uint_is(&f, MT_BASIC_VENDOR_ID, 0xFFF1));
    CHECK(str_is(&f, MT_BASIC_PRODUCT_NAME, "Test Thermostat"));
    CHECK(uint_is(&f, MT_BASIC_PRODUCT_ID, 0x8000));
    CHECK(str_is(&f, MT_BASIC_NODE_LABEL, ""));
    CHECK(str_is(&f, MT_BASIC_LOCATION, "XX"));
    CHECK(uint_is(&f, MT_BASIC_HARDWARE_VERSION, 7));
    CHECK(str_is(&f, MT_BASIC_HARDWARE_VERSION_STRING, "hw-7"));
    CHECK(uint_is(&f, MT_BASIC_SOFTWARE_VERSION, 0x00010203));
    CHECK(str_is(&f, MT_BASIC_SOFTWARE_VERSION_STRING, "1.2.3"));
    CHECK(str_is(&f, MT_BASIC_SERIAL_NUMBER, "SN-0001"));
    CHECK(str_is(&f, MT_BASIC_UNIQUE_ID, "uid-abc"));
    CHECK(uint_is(&f, MT_BASIC_SPECIFICATION_VERSION, 0x01030000));
    CHECK(uint_is(&f, MT_BASIC_MAX_PATHS_PER_INVOKE, 1));
    CHECK(uint_is(&f, 0xFFFD, 3)); /* ClusterRevision */
    CHECK(uint_is(&f, 0xFFFC, 0)); /* FeatureMap */
    /* CapabilityMinima: struct { 0: CASE sessions per fabric, 1: subscriptions per fabric } */
    mt_tlv_rd r;
    uint64_t v;
    CHECK(rd_attr(&f, MT_BASIC_CAPABILITY_MINIMA, 0, &r) == MT_OK && r.type == MT_TLV_STRUCT && mt_tlv_enter(&r) == MT_OK);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_is_ctx(&r, 0) && !mt_tlv_get_u64(&r, &v) && v == 3);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_is_ctx(&r, 1) && !mt_tlv_get_u64(&r, &v) && v == 3);
    CHECK(mt_tlv_next(&r) == MT_ERR_NOT_FOUND);
    /* exact encoding of a short string: anonymous utf8 1-byte length */
    CHECK(rd_attr(&f, MT_BASIC_LOCATION, 0, &r) == MT_OK);
    CHECK(g_buf[0] == 0x0C && g_buf[1] == 2 && g_buf[2] == 'X' && g_buf[3] == 'X');
    /* attributes not implemented (optional ones) are absent from the enumeration */
    mt_im_attr a;
    CHECK(!find_attr(&f, 11, &a) && !find_attr(&f, 17, &a) && !find_attr(&f, 20, &a));
}

static void test_attribute_list_and_flags(void)
{
    fix f;
    mt_tlv_rd r;
    fix_init(&f, NULL);
    static const uint32_t want[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 18, 19, 21, 22,
                                     0xFFF8, 0xFFF9, 0xFFFA, 0xFFFB, 0xFFFC, 0xFFFD };
    /* AttributeList: own attributes then the globals this cluster has (EventList because it has an event) */
    unsigned n = 0;
    uint64_t v;
    for (uint16_t i = 0;; i++) {
        mt_err e = rd_attr(&f, 0xFFFB, i, &r);
        if (e) { CHECK(e == MT_ERR_NOT_FOUND || e == MT_ERR_INVALID); break; }
        CHECK(!mt_tlv_get_u64(&r, &v));
        CHECK(n < sizeof want / sizeof want[0] && v == want[n]);
        n++;
    }
    CHECK(n == sizeof want / sizeof want[0]);
    /* EventList = [StartUp] */
    CHECK(rd_attr(&f, 0xFFFA, 0, &r) == MT_OK && !mt_tlv_get_u64(&r, &v) && v == 0);
    CHECK(rd_attr(&f, 0xFFFA, 1, &r) == MT_ERR_NOT_FOUND);
    /* no commands */
    CHECK(rd_attr(&f, 0xFFF9, 0, &r) == MT_ERR_NOT_FOUND);
    CHECK(rd_attr(&f, 0xFFF8, 0, &r) == MT_ERR_NOT_FOUND);
    /* quality flags and privileges */
    mt_im_attr a;
    CHECK(find_attr(&f, MT_BASIC_NODE_LABEL, &a) && (a.flags & MT_IM_ATTR_WRITABLE) && !(a.flags & MT_IM_ATTR_FIXED));
    CHECK(a.write_priv == MT_IM_PRIV_MANAGE && a.read_priv == MT_IM_PRIV_VIEW);
    CHECK(find_attr(&f, MT_BASIC_LOCATION, &a) && (a.flags & MT_IM_ATTR_WRITABLE) && a.write_priv == MT_IM_PRIV_ADMINISTER);
    CHECK(find_attr(&f, MT_BASIC_VENDOR_ID, &a) && (a.flags & MT_IM_ATTR_FIXED) && !(a.flags & MT_IM_ATTR_WRITABLE));
    CHECK(find_attr(&f, MT_BASIC_CAPABILITY_MINIMA, &a) && (a.flags & MT_IM_ATTR_FIXED));
    /* fixed attributes refuse writes */
    CHECK(wr_str(&f, MT_BASIC_VENDOR_NAME, "x", 1) == MT_IM_UNSUPPORTED_WRITE);
    /* startup event fields {0: SoftwareVersion 0x00010203} */
    uint8_t ev[16];
    size_t n_ev = mt_basic_startup_fields(&f.b, ev, sizeof ev);
    CHECK(n_ev == 6 && ev[0] == 0x26 && ev[1] == 0x00 && mt_get_le32(ev + 2) == 0x00010203);
    CHECK(mt_basic_startup_fields(&f.b, ev, 2) == 0);
}

static void test_write_and_persistence(void)
{
    kv_fake k = { 0 };
    mt_kv_ops ops = kv_ops(&k);
    fix f;
    fix_init(&f, &ops);
    uint32_t v0 = 0, v1 = 0;
    CHECK(mt_dm_dataver(&f.dm, 0, MT_BASIC_CLUSTER_ID, &v0));
    CHECK(wr_str(&f, MT_BASIC_NODE_LABEL, "Kitchen0", 8) == MT_IM_SUCCESS);
    CHECK(str_is(&f, MT_BASIC_NODE_LABEL, "Kitchen0"));
    CHECK(mt_dm_dataver(&f.dm, 0, MT_BASIC_CLUSTER_ID, &v1) && v1 == v0 + 1);
    CHECK(wr_str(&f, MT_BASIC_LOCATION, "DE", 2) == MT_IM_SUCCESS);
    CHECK(str_is(&f, MT_BASIC_LOCATION, "DE"));
    CHECK(k.finishes == 2);
    /* longest label */
    char l32[33];
    memset(l32, 'a', 32);
    l32[32] = 0;
    CHECK(wr_str(&f, MT_BASIC_NODE_LABEL, l32, 32) == MT_IM_SUCCESS);
    CHECK(str_is(&f, MT_BASIC_NODE_LABEL, l32));
    CHECK(wr_str(&f, MT_BASIC_NODE_LABEL, "Kitchen0", 8) == MT_IM_SUCCESS);
    /* constraint and type errors leave value, storage and data version alone */
    int fin = k.finishes;
    CHECK(wr_str(&f, MT_BASIC_NODE_LABEL, "0123456789012345678901234567890123", 34) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr_str(&f, MT_BASIC_LOCATION, "D", 1) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr_str(&f, MT_BASIC_LOCATION, "DEU", 3) == MT_IM_CONSTRAINT_ERROR);
    CHECK(wr_str(&f, MT_BASIC_LOCATION, "D\0", 2) == MT_IM_CONSTRAINT_ERROR);       /* embedded NUL */
    CHECK(wr_str(&f, MT_BASIC_NODE_LABEL, "Bath\0room", 9) == MT_IM_CONSTRAINT_ERROR);
    {
        mt_im_attr a;
        uint8_t buf[8];
        mt_tlv_wr w;
        mt_tlv_rd r;
        mt_im_wctx wc = { NULL, false, false };
        CHECK(find_attr(&f, MT_BASIC_NODE_LABEL, &a));
        mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
        mt_tlv_put_u(&w, mt_tlv_anon(), 5);
        mt_tlv_rd_init(&r, mt_tlv_wr_span(&w));
        mt_tlv_next(&r);
        CHECK(mt_dm_im.write(&f.dm, &wc, &a, MT_IM_WR_VALUE, &r) == MT_IM_INVALID_DATA_TYPE);
        mt_tlv_rd_init(&r, mt_tlv_wr_span(&w));
        mt_tlv_next(&r);
        CHECK(mt_dm_im.write(&f.dm, &wc, &a, MT_IM_WR_LIST_APPEND, &r) == MT_IM_INVALID_ACTION);
    }
    CHECK(k.finishes == fin);
    CHECK(str_is(&f, MT_BASIC_NODE_LABEL, "Kitchen0") && str_is(&f, MT_BASIC_LOCATION, "DE"));
    CHECK(mt_dm_dataver(&f.dm, 0, MT_BASIC_CLUSTER_ID, &v1) && v1 == v0 + 4);
    /* survives a re-init on the same storage */
    fix g;
    fix_init(&g, &ops);
    CHECK(str_is(&g, MT_BASIC_NODE_LABEL, "Kitchen0") && str_is(&g, MT_BASIC_LOCATION, "DE"));
}

static void test_storage_failures(void)
{
    kv_fake k = { 0 };
    mt_kv_ops ops = kv_ops(&k);
    fix f;
    fix_init(&f, &ops);
    CHECK(wr_str(&f, MT_BASIC_NODE_LABEL, "one", 3) == MT_IM_SUCCESS);
    uint32_t v0 = 0, v1 = 0;
    mt_dm_dataver(&f.dm, 0, MT_BASIC_CLUSTER_ID, &v0);
    k.fail_set = true;
    CHECK(wr_str(&f, MT_BASIC_NODE_LABEL, "two", 3) == MT_IM_FAILURE);
    k.fail_set = false;
    k.fail_finish = true;
    CHECK(wr_str(&f, MT_BASIC_NODE_LABEL, "two", 3) == MT_IM_FAILURE);
    k.fail_finish = false;
    CHECK(str_is(&f, MT_BASIC_NODE_LABEL, "one"));
    CHECK(mt_dm_dataver(&f.dm, 0, MT_BASIC_CLUSTER_ID, &v1) && v1 == v0);
    fix g;
    fix_init(&g, &ops);
    CHECK(str_is(&g, MT_BASIC_NODE_LABEL, "one"));
    /* no kv: writes work in RAM only */
    fix h;
    fix_init(&h, NULL);
    CHECK(wr_str(&h, MT_BASIC_NODE_LABEL, "ram", 3) == MT_IM_SUCCESS && str_is(&h, MT_BASIC_NODE_LABEL, "ram"));
}

static void test_corrupt_record_and_init_checks(void)
{
    kv_fake k = { 0 };
    mt_kv_ops ops = kv_ops(&k);
    fix f;
    /* garbage, truncated, wrong types, oversized label, wrong location length: defaults stay */
    static const struct { uint8_t b[40]; size_t n; } bad[] = {
        { { 0xFF, 0x00, 0x01 }, 3 },
        { { 0x15, 0x0C, 0x01, 'a' }, 4 },                                  /* unterminated struct, label length lies */
        { { 0x15, 0x24, 0x01, 0x05, 0x24, 0x02, 0x05, 0x18 }, 8 },         /* ints instead of strings */
        { { 0x15, 0x2C, 0x01, 0x01, 'a', 0x2C, 0x02, 0x01, 'D', 0x18 }, 10 }, /* location of one char */
        { { 0x15, 0x2C, 0x01, 0x01, 'a', 0x18 }, 6 },                      /* location missing */
    };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        memset(&k, 0, sizeof k);
        k.applied[0].used = true;
        k.applied[0].key = KEY;
        memcpy(k.applied[0].v, bad[i].b, bad[i].n);
        k.applied[0].n = bad[i].n;
        fix_init(&f, &ops);
        CHECK(str_is(&f, MT_BASIC_NODE_LABEL, "") && str_is(&f, MT_BASIC_LOCATION, "XX"));
    }
    /* a good hand-made record loads */
    memset(&k, 0, sizeof k);
    static const uint8_t good[] = { 0x15, 0x2C, 0x01, 0x03, 'a', 'b', 'c', 0x2C, 0x02, 0x02, 'N', 'L', 0x18 };
    k.applied[0].used = true;
    k.applied[0].key = KEY;
    memcpy(k.applied[0].v, good, sizeof good);
    k.applied[0].n = sizeof good;
    fix_init(&f, &ops);
    CHECK(str_is(&f, MT_BASIC_NODE_LABEL, "abc") && str_is(&f, MT_BASIC_LOCATION, "NL"));
    /* what we write is that format */
    CHECK(wr_str(&f, MT_BASIC_NODE_LABEL, "abc", 3) == MT_IM_SUCCESS);
    CHECK(k.applied[0].n == sizeof good && !memcmp(k.applied[0].v, good, sizeof good));
    /* a config without a string is refused */
    mt_basic b;
    mt_basic_cfg c = CFG;
    c.serial_number = NULL;
    CHECK(mt_basic_init(&b, &c, NULL, 0) == MT_ERR_INVALID);
}

static void test_chunked_wildcard_read(void)
{
    /* every attribute of the cluster fits a 64-byte buffer one item at a time, none needs more than 64 */
    fix f;
    fix_init(&f, NULL);
    mt_im_attr a;
    unsigned count = 0;
    for (uint16_t i = 0; !mt_dm_im.attr_at(&f.dm, i, &a); i++) {
        if (a.cluster != MT_BASIC_CLUSTER_ID) continue;
        mt_tlv_wr w;
        mt_im_rctx rc = { NULL, false };
        uint8_t buf[64];
        mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
        mt_err e = mt_dm_im.read(&f.dm, &rc, &a, 0, &w, mt_tlv_anon());
        CHECK(e == MT_OK || e == MT_ERR_NOT_FOUND); /* empty lists have no item 0 */
        count++;
    }
    CHECK(count == 16 + 6);
    /* a too-small buffer is reported, not truncated, and leaves the writer unchanged */
    CHECK(find_attr(&f, MT_BASIC_VENDOR_NAME, &a));
    uint8_t tiny[4];
    mt_tlv_wr w;
    mt_im_rctx rc = { NULL, false };
    mt_tlv_wr_init(&w, mt_buf_of(tiny, sizeof tiny));
    CHECK(mt_dm_im.read(&f.dm, &rc, &a, 0, &w, mt_tlv_anon()) == MT_ERR_BUFFER_TOO_SMALL && w.len == 0);
    CHECK(find_attr(&f, MT_BASIC_CAPABILITY_MINIMA, &a));
    mt_tlv_wr_init(&w, mt_buf_of(tiny, 6));
    CHECK(mt_dm_im.read(&f.dm, &rc, &a, 0, &w, mt_tlv_anon()) == MT_ERR_BUFFER_TOO_SMALL && w.len == 0 && w.depth == 0);
}

void test_comm(void); /* test_comm.c */

int main(void)
{
    test_values();
    test_attribute_list_and_flags();
    test_write_and_persistence();
    test_storage_failures();
    test_corrupt_record_and_init_checks();
    test_chunked_wildcard_read();
    test_comm();
    printf("%d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
