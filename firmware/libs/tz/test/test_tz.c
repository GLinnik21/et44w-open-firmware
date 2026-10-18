#include "harness.h"
#include "tz.h"

int t_checks, t_fails;

static void Expect(const tz_civil *c, int y, int mo, int d, int h, int mi, int s, int wd)
{
    CHECK_EQ(c->year, y);
    CHECK_EQ(c->month, mo);
    CHECK_EQ(c->day, d);
    CHECK_EQ(c->hour, h);
    CHECK_EQ(c->minute, mi);
    CHECK_EQ(c->second, s);
    CHECK_EQ(c->weekday, wd);
}

static void test_civil(void)
{
    tz_civil c;
    tz_civil_from_epoch(0, &c);
    Expect(&c, 1970, 1, 1, 0, 0, 0, 4);
    tz_civil_from_epoch(1792238400, &c); /* 2026-10-17 12:00 UTC, Saturday */
    Expect(&c, 2026, 10, 17, 12, 0, 0, 6);
    tz_civil_from_epoch(1835481599, &c); /* leap day */
    Expect(&c, 2028, 2, 29, 23, 59, 59, 2);
    tz_civil_from_epoch(4107542400, &c); /* 2100 is not a leap year */
    Expect(&c, 2100, 3, 1, 0, 0, 0, 1);
}

static void test_fixed(void)
{
    tz_zone z;
    CHECK(tz_parse("JST-9", &z));
    CHECK(!z.has_dst);
    CHECK_EQ(z.std_offset, 9 * 3600);
    tz_civil c;
    tz_local(&z, 1792238400, &c);
    Expect(&c, 2026, 10, 17, 21, 0, 0, 6);
    tz_local(&z, 1792238400 + 3 * 3600, &c); /* 15:00 UTC -> Sunday 00:00 local */
    Expect(&c, 2026, 10, 18, 0, 0, 0, 7);
    CHECK(tz_parse("UTC0", &z));
    CHECK_EQ(z.std_offset, 0);
    CHECK(tz_parse("<-0530>+5:30", &z));
    CHECK_EQ(z.std_offset, -(5 * 3600 + 1800));
}

static void test_cet(void)
{
    tz_zone z;
    CHECK(tz_parse("CET-1CEST,M3.5.0,M10.5.0/3", &z));
    CHECK(z.has_dst);
    CHECK_EQ(z.std_offset, 3600);
    CHECK_EQ(z.dst_offset, 7200);
    tz_civil c;
    tz_local(&z, 1774745999, &c); /* 2026-03-29 00:59:59Z: still CET */
    Expect(&c, 2026, 3, 29, 1, 59, 59, 7);
    tz_local(&z, 1774746000, &c); /* 01:00Z: CEST, 03:00 local */
    Expect(&c, 2026, 3, 29, 3, 0, 0, 7);
    tz_local(&z, 1792889999, &c); /* 2026-10-25 00:59:59Z: still CEST */
    Expect(&c, 2026, 10, 25, 2, 59, 59, 7);
    tz_local(&z, 1792890000, &c); /* 01:00Z: back to CET, 02:00 local */
    Expect(&c, 2026, 10, 25, 2, 0, 0, 7);
    tz_local(&z, 1792238400, &c); /* mid-October: CEST */
    CHECK_EQ(c.hour, 14);
}

static void test_southern(void)
{
    tz_zone z; /* Sydney: DST from first Sunday of October to first Sunday of April */
    CHECK(tz_parse("AEST-10AEDT,M10.1.0,M4.1.0/3", &z));
    tz_civil c;
    tz_local(&z, 1767225600, &c); /* 2026-01-01 00:00Z: summer, UTC+11 */
    CHECK_EQ(c.hour, 11);
    tz_local(&z, 1782864000, &c); /* 2026-07-01 00:00Z: winter, UTC+10 */
    CHECK_EQ(c.hour, 10);
}

static void test_reject(void)
{
    tz_zone z;
    CHECK(!tz_parse("", &z));
    CHECK(!tz_parse(NULL, &z));
    CHECK(!tz_parse("Asia/Tokyo", &z));
    CHECK(!tz_parse("CET-1CEST", &z)); /* DST without rules */
    CHECK(!tz_parse("CET-1CEST,J60,J300", &z));
    CHECK(!tz_parse("CET-1CEST,M13.5.0,M10.5.0", &z));
    CHECK(!tz_parse("<+09-9", &z));
    CHECK_EQ(z.std_offset, 0);
}

int main(void)
{
    RUN(test_civil);
    RUN(test_fixed);
    RUN(test_cet);
    RUN(test_southern);
    RUN(test_reject);
    printf("%d checks, %d failed\n", t_checks, t_fails);
    return t_fails != 0;
}
