/* Host tests for matter-tlv.
 * Vectors: Matter spec 1.3 appendix A.7 (primitive encodings, re-derived by hand from the format
 * rules) and connectedhomeip src/lib/core/tests/TestTLV.cpp (`Encoding1` below is copied verbatim;
 * the test writes the same tree and compares byte for byte, then reads it back). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mt_tlv.h"

static int g_fail, g_checks;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define EQ_ERR(a, e) CHECK((a) == (e))
#define BYTES(...) ((const uint8_t[]){ __VA_ARGS__ })
#define MATCH(w, ...) (mt_tlv_wr_span(&(w)).len == sizeof(BYTES(__VA_ARGS__)) && \
    !memcmp(mt_tlv_wr_span(&(w)).p, BYTES(__VA_ARGS__), sizeof(BYTES(__VA_ARGS__))))

// clang-format off
static const uint8_t k_encoding1[] =
{
    0xD5, 0xBB, 0xAA, 0xDD, 0xCC, 0x01, 0x00, 0xC9, 0xBB, 0xAA, 0xDD, 0xCC, 0x02, 0x00, 0x88, 0x02,
    0x00, 0x36, 0x00, 0x00, 0x2A, 0x00, 0xEF, 0x02, 0xF0, 0x67, 0xFD, 0xFF, 0x07, 0x00, 0x90, 0x2F,
    0x50, 0x09, 0x00, 0x00, 0x00, 0x15, 0x18, 0x17, 0xD4, 0xBB, 0xAA, 0xDD, 0xCC, 0x11, 0x00, 0xB4,
    0xA0, 0xBB, 0x0D, 0x00, 0x14, 0xB5, 0x00, 0x28, 0x6B, 0xEE, 0x6D, 0x70, 0x11, 0x01, 0x00, 0x0E,
    0x01, 0x53, 0x54, 0x41, 0x52, 0x54, 0x2E, 0x2E, 0x2E, 0x21, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x40, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x23, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x24, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x25, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x5E, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x26, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x2A, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x28, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x29, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x2D, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x3D, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x5B, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x5D, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x3B, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x27, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x2E, 0x2E, 0x2E, 0x45, 0x4E, 0x44, 0x18,
    0x18, 0x18, 0xCC, 0xBB, 0xAA, 0xDD, 0xCC, 0x05, 0x00, 0x0E, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69,
    0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x8A, 0xFF, 0xFF, 0x33, 0x33, 0x8F, 0x41, 0xAB,
    0x00, 0x00, 0x01, 0x00, 0x66, 0x66, 0x66, 0x66, 0x66, 0xE6, 0x31, 0x40, 0x18
};

static const char k_large[] =
    "START..."
    "!123456789ABCDEF@123456789ABCDEF#123456789ABCDEF$123456789ABCDEF%123456789ABCDEF^123456789ABCDEF&123456789ABCDEF*123456789ABCDEF"
    "01234567(9ABCDEF01234567)9ABCDEF01234567-9ABCDEF01234567=9ABCDEF01234567[9ABCDEF01234567]9ABCDEF01234567;9ABCDEF01234567'9ABCDEF"
    "...END";

/* TestProfile_1 = 0xAABBCCDD, TestProfile_2 = 0x11223344 (vendor<<16 | profile). TestTLV's writer
 * has TestProfile_2 as its implicit profile, which is why those tags come out in implicit form. */
#define P1(n) mt_tlv_fq(0xAABB, 0xCCDD, (n))
#define P2(n) mt_tlv_implicit(n)
#define ANON mt_tlv_anon()
#define CTX(n) mt_tlv_ctx(n)

static mt_tlv_wr new_wr(uint8_t *buf, size_t cap)
{
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, mt_buf_of(buf, cap));
    return w;
}

static mt_tlv_rd new_rd(const void *p, size_t n)
{
    mt_tlv_rd r;
    mt_tlv_rd_init(&r, mt_span_of(p, n));
    return r;
}

/* Visit every element, entering all containers. Returns the first error, or OK at a clean end. */
static mt_err walk(mt_span in, size_t *count)
{
    mt_tlv_rd r;
    size_t depth = 0;
    mt_tlv_rd_init(&r, in);
    *count = 0;
    for (;;) {
        mt_err e = mt_tlv_next(&r);
        if (e == MT_OK) {
            (*count)++;
            if (mt_tlv_is_container(&r)) { depth++; if ((e = mt_tlv_enter(&r))) return e; }
        } else if (e == MT_ERR_NOT_FOUND) {
            if (!depth) return MT_OK;
            depth--;
            if ((e = mt_tlv_exit(&r))) return e;
        } else {
            return e;
        }
    }
}

static void test_spec_primitives(void)
{
    uint8_t b[32];
    mt_tlv_wr w;
    w = new_wr(b, sizeof b); mt_tlv_put_bool(&w, ANON, false); CHECK(MATCH(w, 0x08));
    w = new_wr(b, sizeof b); mt_tlv_put_bool(&w, ANON, true); CHECK(MATCH(w, 0x09));
    w = new_wr(b, sizeof b); mt_tlv_put_i(&w, ANON, 42); CHECK(MATCH(w, 0x00, 0x2a));
    w = new_wr(b, sizeof b); mt_tlv_put_i(&w, ANON, -17); CHECK(MATCH(w, 0x00, 0xef));
    w = new_wr(b, sizeof b); mt_tlv_put_u(&w, ANON, 42); CHECK(MATCH(w, 0x04, 0x2a));
    w = new_wr(b, sizeof b); mt_tlv_put_i(&w, ANON, -170000); CHECK(MATCH(w, 0x02, 0xf0, 0x67, 0xfd, 0xff));
    w = new_wr(b, sizeof b); mt_tlv_put_i(&w, ANON, 40000000000LL);
    CHECK(MATCH(w, 0x03, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00));
    w = new_wr(b, sizeof b); mt_tlv_put_utf8(&w, ANON, "Hello!", 6);
    CHECK(MATCH(w, 0x0c, 0x06, 'H', 'e', 'l', 'l', 'o', '!'));
    w = new_wr(b, sizeof b); mt_tlv_put_utf8(&w, ANON, "Tsch\xc3\xbc\xc3\x9f", 8);
    CHECK(MATCH(w, 0x0c, 0x08, 'T', 's', 'c', 'h', 0xc3, 0xbc, 0xc3, 0x9f));
    w = new_wr(b, sizeof b); mt_tlv_put_bytes(&w, ANON, mt_span_of(BYTES(0, 1, 2, 3, 4), 5));
    CHECK(MATCH(w, 0x10, 0x05, 0, 1, 2, 3, 4));
    w = new_wr(b, sizeof b); mt_tlv_put_null(&w, ANON); CHECK(MATCH(w, 0x14));
    w = new_wr(b, sizeof b); mt_tlv_put_f32(&w, ANON, 0.0f); CHECK(MATCH(w, 0x0a, 0, 0, 0, 0));
    w = new_wr(b, sizeof b); mt_tlv_put_f32(&w, ANON, 17.9f); CHECK(MATCH(w, 0x0a, 0x33, 0x33, 0x8f, 0x41));
    w = new_wr(b, sizeof b); mt_tlv_put_f64(&w, ANON, 17.9);
    CHECK(MATCH(w, 0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40));
    w = new_wr(b, sizeof b); mt_tlv_start(&w, ANON, MT_TLV_STRUCT); mt_tlv_end(&w); CHECK(MATCH(w, 0x15, 0x18));
    w = new_wr(b, sizeof b); mt_tlv_start(&w, ANON, MT_TLV_ARRAY); mt_tlv_end(&w); CHECK(MATCH(w, 0x16, 0x18));
    w = new_wr(b, sizeof b); mt_tlv_start(&w, ANON, MT_TLV_LIST); mt_tlv_end(&w); CHECK(MATCH(w, 0x17, 0x18));
    w = new_wr(b, sizeof b);   /* only the three container types open a container */
    CHECK(mt_tlv_start(&w, ANON, (mt_tlv_type)(MT_TLV_LIST + 1)) == MT_ERR_INVALID && w.len == 0 && w.depth == 0);

    /* array [0,1,2,3,4], structure {0: 42, 1: -17} with signed context tags */
    w = new_wr(b, sizeof b); mt_tlv_start(&w, ANON, MT_TLV_ARRAY);
    for (int i = 0; i < 5; i++) mt_tlv_put_i(&w, ANON, i);
    mt_tlv_end(&w);
    CHECK(MATCH(w, 0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x18));
    w = new_wr(b, sizeof b); mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_put_i(&w, CTX(0), 42); mt_tlv_put_i(&w, CTX(1), -17); mt_tlv_end(&w);
    CHECK(MATCH(w, 0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18));

    /* the eight tag forms, unsigned 42 */
    w = new_wr(b, sizeof b); mt_tlv_put_u(&w, mt_tlv_common(0x0102), 42); CHECK(MATCH(w, 0x44, 0x02, 0x01, 0x2a));
    w = new_wr(b, sizeof b); mt_tlv_put_u(&w, mt_tlv_common(0x01020304), 42);
    CHECK(MATCH(w, 0x64, 0x04, 0x03, 0x02, 0x01, 0x2a));
    w = new_wr(b, sizeof b); mt_tlv_put_u(&w, mt_tlv_implicit(0x0102), 42); CHECK(MATCH(w, 0x84, 0x02, 0x01, 0x2a));
    w = new_wr(b, sizeof b); mt_tlv_put_u(&w, mt_tlv_implicit(0x01020304), 42);
    CHECK(MATCH(w, 0xa4, 0x04, 0x03, 0x02, 0x01, 0x2a));
    w = new_wr(b, sizeof b); mt_tlv_put_u(&w, mt_tlv_fq(0xFFF1, 0xDEED, 1), 42);
    CHECK(MATCH(w, 0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a));
    w = new_wr(b, sizeof b); mt_tlv_put_u(&w, mt_tlv_fq(0xFFF1, 0xDEED, 0xAA55FEED), 42);
    CHECK(MATCH(w, 0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a));
}

static void expect_u(mt_tlv_rd *r, uint64_t v)
{
    uint64_t got = 0;
    CHECK(mt_tlv_next(r) == MT_OK && mt_tlv_get_u64(r, &got) == MT_OK && got == v);
}

static void test_encoding1_write(void)
{
    uint8_t b[512];
    mt_tlv_wr w = new_wr(b, sizeof b);
    CHECK(mt_tlv_start(&w, P1(1), MT_TLV_STRUCT) == MT_OK);
    mt_tlv_put_bool(&w, P1(2), true);
    mt_tlv_put_bool(&w, P2(2), false);
    mt_tlv_start(&w, CTX(0), MT_TLV_ARRAY);
    mt_tlv_put_i(&w, ANON, 42);
    mt_tlv_put_i(&w, ANON, -17);
    mt_tlv_put_i(&w, ANON, -170000);
    mt_tlv_put_u(&w, ANON, 40000000000ULL);
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT); mt_tlv_end(&w);
    mt_tlv_start(&w, ANON, MT_TLV_LIST);
    mt_tlv_put_null(&w, P1(17));
    mt_tlv_put_null(&w, P2(900000));
    mt_tlv_put_null(&w, ANON);
    mt_tlv_start(&w, P2(4000000000u), MT_TLV_STRUCT);
    mt_tlv_put_utf8(&w, mt_tlv_common(70000), k_large, strlen(k_large));
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    mt_tlv_put_utf8(&w, P1(5), "This is a test", 14);
    mt_tlv_put_f32(&w, P2(65535), 17.9f);
    mt_tlv_put_f64(&w, P2(65536), 17.9);
    mt_tlv_end(&w);
    mt_span out;
    CHECK(mt_tlv_wr_done(&w, &out) == MT_OK);
    CHECK(out.len == sizeof k_encoding1 && !memcmp(out.p, k_encoding1, out.len));
}

static void test_encoding1_read(void)
{
    mt_tlv_rd r = new_rd(k_encoding1, sizeof k_encoding1);
    mt_span s;
    bool bv;
    float f;
    double d;
    int64_t i;

    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_STRUCT && mt_tlv_tag_eq(r.tag, P1(1)));
    CHECK(mt_tlv_enter(&r) == MT_OK);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_get_bool(&r, &bv) == MT_OK && bv && mt_tlv_tag_eq(r.tag, P1(2)));
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_get_bool(&r, &bv) == MT_OK && !bv && mt_tlv_tag_eq(r.tag, P2(2)));
    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_ARRAY && mt_tlv_is_ctx(&r, 0));
    CHECK(mt_tlv_enter(&r) == MT_OK);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_get_i64(&r, &i) == MT_OK && i == 42);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_get_i64(&r, &i) == MT_OK && i == -17);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_get_i64(&r, &i) == MT_OK && i == -170000);
    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_UINT && r.val == 40000000000ULL);
    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_STRUCT);
    CHECK(mt_tlv_enter(&r) == MT_OK && mt_tlv_next(&r) == MT_ERR_NOT_FOUND && mt_tlv_exit(&r) == MT_OK);
    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_LIST);
    CHECK(mt_tlv_enter(&r) == MT_OK);
    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_NULL && mt_tlv_tag_eq(r.tag, P1(17)));
    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_NULL && mt_tlv_tag_eq(r.tag, P2(900000)));
    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_NULL && r.tag.kind == MT_TAG_ANON);
    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_STRUCT && mt_tlv_tag_eq(r.tag, P2(4000000000u)));
    CHECK(mt_tlv_enter(&r) == MT_OK && mt_tlv_next(&r) == MT_OK);
    CHECK(mt_tlv_tag_eq(r.tag, mt_tlv_common(70000)) && mt_tlv_get_utf8(&r, &s) == MT_OK);
    CHECK(s.len == strlen(k_large) && !memcmp(s.p, k_large, s.len));
    CHECK(mt_tlv_get_bytes(&r, &s) == MT_ERR_INVALID);
    CHECK(mt_tlv_next(&r) == MT_ERR_NOT_FOUND && mt_tlv_exit(&r) == MT_OK); /* big struct */
    CHECK(mt_tlv_next(&r) == MT_ERR_NOT_FOUND && mt_tlv_exit(&r) == MT_OK); /* list */
    CHECK(mt_tlv_next(&r) == MT_ERR_NOT_FOUND && mt_tlv_exit(&r) == MT_OK); /* array */
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_get_utf8(&r, &s) == MT_OK && s.len == 14 && !memcmp(s.p, "This is a test", 14));
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_get_f32(&r, &f) == MT_OK && f == 17.9f);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_get_f64(&r, &d) == MT_OK && d == 17.9);
    CHECK(mt_tlv_get_f32(&r, &f) == MT_ERR_INVALID);
    CHECK(mt_tlv_next(&r) == MT_ERR_NOT_FOUND && mt_tlv_exit(&r) == MT_OK);
    CHECK(mt_tlv_next(&r) == MT_ERR_NOT_FOUND && mt_tlv_next(&r) == MT_ERR_NOT_FOUND); /* sticky end */

    size_t n;
    CHECK(walk(mt_span_of(k_encoding1, sizeof k_encoding1), &n) == MT_OK && n == 18);
}

static void test_int_widths(void)
{
    static const struct { int64_t v; size_t bytes; } si[] = {
        { 0, 1 }, { 127, 1 }, { -128, 1 }, { 128, 2 }, { -129, 2 }, { 32767, 2 }, { -32768, 2 },
        { 32768, 4 }, { -32769, 4 }, { INT32_MAX, 4 }, { INT32_MIN, 4 }, { (int64_t)INT32_MAX + 1, 8 },
        { (int64_t)INT32_MIN - 1, 8 }, { INT64_MAX, 8 }, { INT64_MIN, 8 } };
    static const struct { uint64_t v; size_t bytes; } ui[] = {
        { 0, 1 }, { 255, 1 }, { 256, 2 }, { 65535, 2 }, { 65536, 4 }, { UINT32_MAX, 4 },
        { (uint64_t)UINT32_MAX + 1, 8 }, { UINT64_MAX, 8 } };
    uint8_t b[16];
    for (size_t k = 0; k < sizeof si / sizeof si[0]; k++) {
        mt_tlv_wr w = new_wr(b, sizeof b);
        mt_tlv_rd r;
        int64_t got = 0;
        mt_tlv_put_i(&w, ANON, si[k].v);
        CHECK(w.len == 1 + si[k].bytes);
        r = new_rd(b, w.len);
        CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_SINT && mt_tlv_get_i64(&r, &got) == MT_OK && got == si[k].v);
    }
    for (size_t k = 0; k < sizeof ui / sizeof ui[0]; k++) {
        mt_tlv_wr w = new_wr(b, sizeof b);
        mt_tlv_rd r;
        uint64_t got = 0;
        mt_tlv_put_u(&w, ANON, ui[k].v);
        CHECK(w.len == 1 + ui[k].bytes);
        r = new_rd(b, w.len);
        CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_UINT && mt_tlv_get_u64(&r, &got) == MT_OK && got == ui[k].v);
    }
}

static void test_getter_ranges(void)
{
    uint8_t b[64];
    mt_tlv_wr w = new_wr(b, sizeof b);
    mt_tlv_rd r;
    uint8_t u8; uint16_t u16; uint32_t u32; uint64_t u64; int8_t i8; int16_t i16; int32_t i32; int64_t i64;
    mt_tlv_put_u(&w, ANON, 300);
    mt_tlv_put_i(&w, ANON, -1);
    mt_tlv_put_u(&w, ANON, UINT64_MAX);
    mt_tlv_put_i(&w, ANON, 100000);
    mt_tlv_put_i(&w, ANON, 5);
    mt_tlv_put_bool(&w, ANON, true);
    r = new_rd(b, w.len);

    mt_tlv_next(&r);
    CHECK(mt_tlv_get_u8(&r, &u8) == MT_ERR_INVALID);
    CHECK(mt_tlv_get_u16(&r, &u16) == MT_OK && u16 == 300);
    CHECK(mt_tlv_get_i8(&r, &i8) == MT_ERR_INVALID);
    CHECK(mt_tlv_get_i16(&r, &i16) == MT_OK && i16 == 300);
    mt_tlv_next(&r); /* -1 */
    CHECK(mt_tlv_get_u64(&r, &u64) == MT_ERR_INVALID && mt_tlv_get_u8(&r, &u8) == MT_ERR_INVALID);
    CHECK(mt_tlv_get_i8(&r, &i8) == MT_OK && i8 == -1);
    mt_tlv_next(&r); /* UINT64_MAX */
    CHECK(mt_tlv_get_u64(&r, &u64) == MT_OK && u64 == UINT64_MAX);
    CHECK(mt_tlv_get_i64(&r, &i64) == MT_ERR_INVALID && mt_tlv_get_u32(&r, &u32) == MT_ERR_INVALID);
    mt_tlv_next(&r); /* 100000 */
    CHECK(mt_tlv_get_i16(&r, &i16) == MT_ERR_INVALID && mt_tlv_get_u16(&r, &u16) == MT_ERR_INVALID);
    CHECK(mt_tlv_get_i32(&r, &i32) == MT_OK && i32 == 100000 && mt_tlv_get_u32(&r, &u32) == MT_OK);
    mt_tlv_next(&r); /* signed 5 reads as unsigned */
    CHECK(mt_tlv_get_u8(&r, &u8) == MT_OK && u8 == 5);
    mt_tlv_next(&r); /* bool is not an int */
    CHECK(mt_tlv_get_u8(&r, &u8) == MT_ERR_INVALID && mt_tlv_get_utf8(&r, &(mt_span){0}) == MT_ERR_INVALID);
    CHECK(mt_tlv_next(&r) == MT_ERR_NOT_FOUND);
    CHECK(mt_tlv_get_u8(&r, &u8) == MT_ERR_INVALID); /* no current element */
}

static void test_navigation(void)
{
    /* { 0: 1, 1: [ 10, 20, { 5: 7 } ], 2: 2, 3: { 0: 3 }, 4: 4 } */
    uint8_t b[64];
    mt_tlv_wr w = new_wr(b, sizeof b);
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_put_u(&w, CTX(0), 1);
    mt_tlv_start(&w, CTX(1), MT_TLV_ARRAY);
    mt_tlv_put_u(&w, ANON, 10); mt_tlv_put_u(&w, ANON, 20);
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT); mt_tlv_put_u(&w, CTX(5), 7); mt_tlv_end(&w);
    mt_tlv_end(&w);
    mt_tlv_put_u(&w, CTX(2), 2);
    mt_tlv_start(&w, CTX(3), MT_TLV_STRUCT); mt_tlv_put_u(&w, CTX(0), 3); mt_tlv_end(&w);
    mt_tlv_put_u(&w, CTX(4), 4);
    mt_tlv_end(&w);

    mt_tlv_rd r = new_rd(b, w.len), c;
    uint64_t v;
    mt_tlv_next(&r); mt_tlv_enter(&r);
    c = r; /* find on a copy keeps r in place */
    CHECK(mt_tlv_find_ctx(&c, 4) == MT_OK && mt_tlv_get_u64(&c, &v) == MT_OK && v == 4);
    CHECK(mt_tlv_find_ctx(&c, 9) == MT_ERR_NOT_FOUND);
    c = r;
    CHECK(mt_tlv_find_ctx(&c, 2) == MT_OK && mt_tlv_get_u64(&c, &v) == MT_OK && v == 2); /* skipped the array */
    CHECK(mt_tlv_find_ctx(&c, 5) == MT_ERR_NOT_FOUND); /* tag 5 lives in a nested container */

    expect_u(&r, 1);
    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_ARRAY);
    mt_tlv_enter(&r);
    expect_u(&r, 10);
    CHECK(mt_tlv_exit(&r) == MT_OK); /* leave the array early */
    expect_u(&r, 2);
    CHECK(mt_tlv_next(&r) == MT_OK && r.type == MT_TLV_STRUCT); /* current container, never entered */
    expect_u(&r, 4); /* next() skipped the struct */
    CHECK(mt_tlv_next(&r) == MT_ERR_NOT_FOUND);
    CHECK(mt_tlv_exit(&r) == MT_OK && mt_tlv_exit(&r) == MT_ERR_STATE);
    CHECK(mt_tlv_next(&r) == MT_ERR_NOT_FOUND);

    /* exit while positioned on an un-entered container skips it too */
    r = new_rd(b, w.len);
    mt_tlv_next(&r); mt_tlv_enter(&r);
    mt_tlv_find_ctx(&r, 3);
    CHECK(r.type == MT_TLV_STRUCT && mt_tlv_exit(&r) == MT_OK);
    CHECK(mt_tlv_next(&r) == MT_ERR_NOT_FOUND);
    CHECK(mt_tlv_enter(&r) == MT_ERR_STATE);
}

static void test_writer_limits(void)
{
    uint8_t b[16];
    mt_tlv_wr w = new_wr(b, 6);
    mt_span out;
    CHECK(mt_tlv_put_u(&w, ANON, 1) == MT_OK && w.len == 2);
    CHECK(mt_tlv_put_utf8(&w, ANON, "abcd", 4) == MT_ERR_BUFFER_TOO_SMALL && w.len == 2); /* needs 6, 4 left */
    CHECK(mt_tlv_put_u(&w, mt_tlv_fq(1, 2, 3), 1) == MT_ERR_BUFFER_TOO_SMALL && w.len == 2);
    mt_tlv_tag bad_ctx = { MT_TAG_CTX, 0, 0, 256 };
    CHECK(mt_tlv_put_u(&w, bad_ctx, 1) == MT_ERR_INVALID);
    CHECK(mt_tlv_start(&w, ANON, MT_TLV_BOOL) == MT_ERR_INVALID);
    CHECK(mt_tlv_end(&w) == MT_ERR_STATE);
    CHECK(mt_tlv_put_raw(&w, mt_span_of(BYTES(1, 2, 3, 4, 5), 5)) == MT_ERR_BUFFER_TOO_SMALL);
    CHECK(mt_tlv_put_raw(&w, mt_span_of(BYTES(0x14, 0x14, 0x14, 0x14), 4)) == MT_OK && w.len == 6);
    CHECK(mt_tlv_put_null(&w, ANON) == MT_ERR_BUFFER_TOO_SMALL);

    w = new_wr(b, 16);
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    CHECK(mt_tlv_wr_done(&w, &out) == MT_ERR_STATE);
    mt_tlv_end(&w);
    CHECK(mt_tlv_wr_done(&w, &out) == MT_OK && out.len == 2);

    /* a 300 byte string needs a 2-byte length; 4-byte length form via a 70000 byte payload */
    static uint8_t big[70100], payload[70000];
    memset(payload, 0xAB, sizeof payload);
    w = new_wr(big, sizeof big);
    CHECK(mt_tlv_put_bytes(&w, ANON, mt_span_of(payload, 300)) == MT_OK && big[0] == 0x11 && big[1] == 0x2c && big[2] == 0x01);
    w = new_wr(big, sizeof big);
    CHECK(mt_tlv_put_bytes(&w, ANON, mt_span_of(payload, sizeof payload)) == MT_OK && w.len == 5 + sizeof payload);
    CHECK(big[0] == 0x12 && big[1] == 0x70 && big[2] == 0x11 && big[3] == 1 && big[4] == 0);
    mt_tlv_rd r = new_rd(big, w.len);
    mt_span s;
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_get_bytes(&r, &s) == MT_OK && s.len == sizeof payload);
}

static void test_checkpoint_reserve(void)
{
    /* Chunking: fill a list until it no longer fits, rolling back the item that failed, with room
     * held back for the two closers. */
    uint8_t b[32];
    mt_tlv_wr w = new_wr(b, sizeof b);
    int items = 0;
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_start(&w, CTX(1), MT_TLV_ARRAY);
    w.reserve = 2;
    for (;;) {
        mt_tlv_mark m = mt_tlv_wr_mark(&w);
        mt_err e = mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
        if (!e) e = mt_tlv_put_u(&w, CTX(0), (uint64_t)items);
        if (!e) e = mt_tlv_put_utf8(&w, CTX(1), "xy", 2);
        if (!e) e = mt_tlv_end(&w);
        if (e) { CHECK(e == MT_ERR_BUFFER_TOO_SMALL); mt_tlv_wr_rollback(&w, m); break; }
        items++;
    }
    CHECK(items > 0 && w.depth == 2);
    CHECK(mt_tlv_end(&w) == MT_OK && mt_tlv_end(&w) == MT_OK); /* closers fit thanks to the reserve */
    mt_span out;
    CHECK(mt_tlv_wr_done(&w, &out) == MT_OK);
    size_t n;
    CHECK(walk(out, &n) == MT_OK && n == 2 + (size_t)items * 3);

    /* rollback across container boundaries restores depth */
    w = new_wr(b, sizeof b);
    mt_tlv_start(&w, ANON, MT_TLV_LIST);
    mt_tlv_mark m = mt_tlv_wr_mark(&w);
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_rd rd;
    mt_tlv_wr_rollback(&w, m);
    CHECK(w.depth == 1 && w.len == 1);
    mt_tlv_end(&w);
    rd = new_rd(b, w.len);
    CHECK(walk(mt_tlv_wr_span(&w), &n) == MT_OK && n == 1);
    (void)rd;
}

static void test_malformed(void)
{
    size_t n;
    /* every proper prefix of Encoding1 is truncated somewhere */
    for (size_t k = 0; k < sizeof k_encoding1; k++)
        CHECK(walk(mt_span_of(k_encoding1, k), &n) == MT_ERR_INVALID || k == 0);
    CHECK(walk(mt_span_of(k_encoding1, 0), &n) == MT_OK && n == 0);

    static const struct { uint8_t p[12]; size_t n; } bad[] = {
        { { 0x19 }, 1 }, { { 0x1f }, 1 },                     /* reserved element types */
        { { 0x38 }, 1 },                                         /* end-of-container with a tag */
        { { 0x18 }, 1 },                                         /* end at depth 0 */
        { { 0x15, 0x18, 0x18 }, 3 },                             /* extra end */
        { { 0x15 }, 1 },                                         /* unterminated */
        { { 0x04 }, 1 }, { { 0x07, 1, 2, 3 }, 4 },            /* truncated ints */
        { { 0x24 }, 1 }, { { 0xc4, 1, 2, 3, 4, 5 }, 6 },      /* truncated tags */
        { { 0x0c, 0x05, 'a', 'b' }, 4 },                         /* string longer than input */
        { { 0x0e, 0xff, 0xff, 0xff, 0xff }, 5 },                 /* 4-byte length 4 GiB */
        { { 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, 9 }, /* 8-byte length huge */
        { { 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, 9 },
        { { 0x0f, 0, 0, 0, 0, 0, 0, 0 }, 8 },                   /* truncated length field */
        { { 0x0a, 0, 0, 0 }, 4 }, { { 0x0b, 0, 0, 0, 0, 0, 0, 0 }, 8 }, /* truncated floats */
    };
    for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++)
        CHECK(walk(mt_span_of(bad[k].p, bad[k].n), &n) == MT_ERR_INVALID);

    mt_tlv_rd r = new_rd(BYTES(0x04, 1), 2);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_enter(&r) == MT_ERR_STATE && mt_tlv_exit(&r) == MT_ERR_STATE);

    /* deep nesting is iterative: 100000 nested arrays must not blow the stack */
    static uint8_t deep[200001];
    memset(deep, 0x16, 100000);
    memset(deep + 100000, 0x18, 100000);
    CHECK(walk(mt_span_of(deep, 200000), &n) == MT_OK && n == 100000);
    r = new_rd(deep, 200000);
    CHECK(mt_tlv_next(&r) == MT_OK && mt_tlv_next(&r) == MT_ERR_NOT_FOUND); /* skips the whole tree */

    /* deterministic noise: never crash or read out of bounds (ASan), errors are fine */
    uint32_t x = 12345;
    uint8_t junk[64];
    for (int round = 0; round < 20000; round++) {
        size_t len = 1 + (x >> 8) % sizeof junk;
        for (size_t i = 0; i < len; i++) { x = x * 1664525u + 1013904223u; junk[i] = (uint8_t)(x >> 24); }
        mt_err e = walk(mt_span_of(junk, len), &n);
        CHECK(e == MT_OK || e == MT_ERR_INVALID);
    }
}

/* mt_tlv_open_struct and mt_tlv_get_bytes_len. */
static void test_helpers(void)
{
    mt_tlv_rd r;
    mt_span b;
    /* Named arrays, not BYTES(): the reader keeps pointing into them after EQ_ERR's block ends. */
    static const uint8_t abc[] = {0x15, 0x30, 0x01, 0x03, 'a', 'b', 'c', 0x18}; /* { 1: bytes "abc" } */
    static const uint8_t uint7[] = {0x15, 0x24, 0x01, 0x07, 0x18};
    EQ_ERR(mt_tlv_open_struct(&r, mt_span_of(abc, sizeof abc)), MT_OK);
    EQ_ERR(mt_tlv_next(&r), MT_OK);
    EQ_ERR(mt_tlv_get_bytes_len(&r, 3, 3, &b), MT_OK);
    CHECK(b.len == 3 && b.p[0] == 'a');
    EQ_ERR(mt_tlv_get_bytes_len(&r, 1, 2, &b), MT_ERR_INVALID);
    EQ_ERR(mt_tlv_get_bytes_len(&r, 4, 9, &b), MT_ERR_INVALID);
    EQ_ERR(mt_tlv_next(&r), MT_ERR_NOT_FOUND);
    /* a uint is not a byte string */
    EQ_ERR(mt_tlv_open_struct(&r, mt_span_of(uint7, sizeof uint7)), MT_OK);
    EQ_ERR(mt_tlv_next(&r), MT_OK);
    EQ_ERR(mt_tlv_get_bytes_len(&r, 0, 9, &b), MT_ERR_INVALID);
    /* empty input, an array, a context-tagged struct */
    EQ_ERR(mt_tlv_open_struct(&r, mt_span_of(NULL, 0)), MT_ERR_INVALID);
    EQ_ERR(mt_tlv_open_struct(&r, mt_span_of(BYTES(0x16, 0x18), 2)), MT_ERR_INVALID);
    EQ_ERR(mt_tlv_open_struct(&r, mt_span_of(BYTES(0x35, 0x01, 0x18), 3)), MT_ERR_INVALID);
}

int main(void)
{
    test_spec_primitives();
    test_encoding1_write();
    test_encoding1_read();
    test_int_widths();
    test_getter_ranges();
    test_navigation();
    test_writer_limits();
    test_checkpoint_reserve();
    test_malformed();
    test_helpers();
    printf("matter-tlv: %d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
