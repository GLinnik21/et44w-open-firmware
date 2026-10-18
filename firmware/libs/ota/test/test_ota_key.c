#include "harness.h"
#include "ota_key.h"

int t_checks, t_fails;

static void test_placeholder_refused(void)
{
    uint8_t key[32] = { 0 };
    CHECK(!ota_key_usable(key));
    key[31] = 0x80; /* same point, other sign of x */
    CHECK(!ota_key_usable(key));
}

static void test_small_order_refused(void)
{
    uint8_t key[32] = { 1 };
    CHECK(!ota_key_usable(key)); /* identity */
    memset(key, 0xff, sizeof key);
    for (uint8_t low = 0xec; low <= 0xee; low++) { /* p - 1, p, p + 1 */
        key[0] = low;
        key[31] = 0x7f;
        CHECK(!ota_key_usable(key));
        key[31] = 0xff;
        CHECK(!ota_key_usable(key));
    }
    static const uint8_t order8[32] = { 0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
                                        0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
                                        0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x85 };
    CHECK(!ota_key_usable(order8));
}

static void test_real_key_accepted(void)
{
    /* RFC 8032 section 7.1, test 1 public key */
    static const uint8_t rfc[32] = { 0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
                                     0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
                                     0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a };
    CHECK(ota_key_usable(rfc));
    uint8_t two[32] = { 2 }; /* not a small-order encoding */
    CHECK(ota_key_usable(two));
}

void run_receive_tests(void);
void run_ed25519_tests(void);

int main(void)
{
    RUN(test_placeholder_refused);
    RUN(test_small_order_refused);
    RUN(test_real_key_accepted);
    run_ed25519_tests();
    run_receive_tests();
    printf("%d checks, %d failed\n", t_checks, t_fails);
    return t_fails != 0;
}
