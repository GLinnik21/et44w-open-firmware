#include <stdio.h>
#include <string.h>
#include "mt_core.h"
#include "mbedtls/ccm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void test_le(void) {
    uint8_t b[8];
    mt_put_le64(b, 0x0102030405060708ull);
    CHECK(b[0] == 8 && b[7] == 1);
    CHECK(mt_get_le64(b) == 0x0102030405060708ull);
    CHECK(mt_get_le32(b) == 0x05060708u);
    CHECK(mt_get_le16(b + 6) == 0x0102u);
    mt_put_le32(b, 0xA1B2C3D4u);
    CHECK(b[0] == 0xD4 && b[3] == 0xA1 && mt_get_le32(b) == 0xA1B2C3D4u);
    mt_put_le16(b, 0xBEEF);
    CHECK(b[0] == 0xEF && b[1] == 0xBE);
}

static void test_spans(void) {
    uint8_t raw[4] = { 1, 2, 3, 4 };
    uint8_t same[4] = { 1, 2, 3, 4 }, other[4] = { 1, 2, 3, 5 };
    mt_buf b = mt_buf_of(raw, sizeof raw);
    CHECK(b.p == raw && b.cap == sizeof raw);
    CHECK(mt_span_eq(mt_span_of(raw, 4), mt_span_of(same, 4)) && !mt_span_eq(mt_span_of(raw, 4), mt_span_of(other, 4)));
    CHECK(!mt_span_eq(mt_span_of(raw, 3), mt_span_of(same, 4)) && mt_span_eq(mt_span_of(NULL, 0), mt_span_of(raw, 0)));
    CHECK(mt_ct_eq(raw, same, 4) && !mt_ct_eq(raw, other, 4) && mt_ct_eq(raw, other, 3));
    CHECK(MT_OK == 0 && MT_ERR_INVALID != MT_OK);
}

static mt_err try_twice(mt_err first, int *reached)
{
    MT_TRY(first);
    *reached = 1;
    return MT_OK;
}

static void test_helpers(void) {
    int reached = 0;
    CHECK(try_twice(MT_ERR_IO, &reached) == MT_ERR_IO && !reached);
    CHECK(try_twice(MT_OK, &reached) == MT_OK && reached);
    /* deadlines across the 32-bit wrap */
    CHECK(mt_due(100, 100) && mt_due(101, 100) && !mt_due(99, 100));
    CHECK(mt_due(5, 0xFFFFFFF0u) && !mt_due(0xFFFFFFF0u, 5));
    CHECK(mt_until(0xFFFFFFF0u, 5) == 0x15 && mt_until(10, 5) == 0 && mt_until(5, 10) == 5);
    CHECK(mt_min_u32(3, 7) == 3 && mt_min_u32(7, 3) == 3);
}

/* Smoke test of the host mbedtls build (build/hosttest.mk): SHA-256 and P-256 are linked and work. */
static void test_host_mbedtls(void) {
    /* FIPS 180-2 / NIST CSRC example: SHA-256("abc") */
    static const uint8_t want[8] = { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea };
    uint8_t h[32];
    CHECK(mbedtls_sha256((const uint8_t *)"abc", 3, h, 0) == 0);
    CHECK(memcmp(h, want, sizeof want) == 0);

    mbedtls_ecp_group g;
    mbedtls_ecp_group_init(&g);
    CHECK(mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1) == 0);
    CHECK(mbedtls_ecp_check_pubkey(&g, &g.G) == 0); /* the generator is on the curve */
    mbedtls_ecp_group_free(&g);

    mbedtls_ccm_context ccm;
    mbedtls_ccm_init(&ccm);
    uint8_t key[16] = { 0 };
    CHECK(mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, 128) == 0);
    mbedtls_ccm_free(&ccm);
}

int main(void) {
    test_le();
    test_spans();
    test_helpers();
    test_host_mbedtls();
    puts(fails ? "matter-core: FAILED" : "matter-core: ok");
    return fails != 0;
}
