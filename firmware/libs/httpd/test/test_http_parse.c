#include <string.h>

#include "harness.h"
#include "http_parse.h"

int t_checks, t_fails;

static int Parse(const char *text, char *buf, size_t cap, http_request *rq)
{
    size_t n = strlen(text);
    if (n >= cap) return -2;
    memcpy(buf, text, n + 1);
    return http_parse(buf, n, rq);
}

static void test_get(void)
{
    char buf[512];
    http_request rq;
    const char *req = "GET /api/state?x=1 HTTP/1.1\r\nHost: 192.168.1.50\r\nAccept: */*\r\n\r\nrest";
    CHECK_EQ(Parse(req, buf, sizeof buf, &rq), 1);
    CHECK(!strcmp(rq.method, "GET"));
    CHECK(!strcmp(rq.path, "/api/state"));
    CHECK(!strcmp(rq.query, "x=1"));
    CHECK(!strcmp(rq.host, "192.168.1.50"));
    CHECK(!rq.requested_with);
    CHECK_EQ(rq.content_length, 0);
    CHECK_EQ(rq.header_len, strlen(req) - 4);
}

static void test_post_headers(void)
{
    char buf[512];
    http_request rq;
    const char *req = "POST /api/dp HTTP/1.1\r\nhost:  hap-a1b2c3.local:80 \r\ncontent-length: 9\r\n"
                      "X-Requested-With: thermo\r\n\r\ndp=16&v=1";
    CHECK_EQ(Parse(req, buf, sizeof buf, &rq), 1);
    CHECK(!strcmp(rq.method, "POST"));
    CHECK(!strcmp(rq.query, ""));
    CHECK(!strcmp(rq.host, "hap-a1b2c3.local:80"));
    CHECK(rq.requested_with);
    CHECK_EQ(rq.content_length, 9);
    CHECK(!strcmp(buf + rq.header_len, "dp=16&v=1"));
}

static void test_incomplete_and_malformed(void)
{
    char buf[512];
    http_request rq;
    CHECK_EQ(Parse("GET / HTTP/1.1\r\nHost: a\r\n", buf, sizeof buf, &rq), 0);
    CHECK(!strcmp(buf, "GET / HTTP/1.1\r\nHost: a\r\n")); /* untouched */
    CHECK_EQ(Parse("GET /\r\n\r\n", buf, sizeof buf, &rq), -1);
    CHECK_EQ(Parse("GET x HTTP/1.1\r\n\r\n", buf, sizeof buf, &rq), -1);
    CHECK_EQ(Parse("GET / SPDY/1\r\n\r\n", buf, sizeof buf, &rq), -1);
    CHECK_EQ(Parse("GET / HTTP/1.1\r\nNoColon\r\n\r\n", buf, sizeof buf, &rq), -1);
    CHECK_EQ(Parse("POST / HTTP/1.1\r\nContent-Length: 12x\r\n\r\n", buf, sizeof buf, &rq), -1);
    CHECK_EQ(Parse("POST / HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n", buf, sizeof buf, &rq), -1);
    CHECK_EQ(Parse("\r\n\r\n", buf, sizeof buf, &rq), -1);
    CHECK_EQ(Parse("GET / HTTP/1.0\r\n\r\n", buf, sizeof buf, &rq), 1);
    CHECK(!strcmp(rq.host, ""));
    /* an embedded NUL would end the header loop early, after the Host line but before the X- header */
    static const char nul[] = "POST / HTTP/1.1\r\nHost: a.local\r\n\0X-Requested-With: x\r\n\r\n";
    memcpy(buf, nul, sizeof nul);
    CHECK_EQ(http_parse(buf, sizeof nul - 1, &rq), -1);
    static const char body_nul[] = "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\na\0b"; /* the body is not checked */
    memcpy(buf, body_nul, sizeof body_nul);
    CHECK_EQ(http_parse(buf, sizeof body_nul - 1, &rq), 1);
}

static void test_host(void)
{
    CHECK(http_host_is_local("192.168.1.50"));
    CHECK(http_host_is_local("192.168.1.50:80"));
    CHECK(http_host_is_local("hap-a1b2c3.local"));
    CHECK(http_host_is_local("HAP-A1B2C3.LOCAL:8080"));
    CHECK(!http_host_is_local(""));
    CHECK(!http_host_is_local(".local"));
    CHECK(!http_host_is_local("evil.example.com"));
    CHECK(!http_host_is_local("local"));
    CHECK(!http_host_is_local("evil.local.example.com"));
    CHECK(!http_host_is_local("192.168.1"));
    CHECK(!http_host_is_local("192.168.1.1234"));
    CHECK(!http_host_is_local("1..2.3"));
    CHECK(!http_host_is_local("192.168.1.50:"));
    CHECK(!http_host_is_local("192.168.1.50:8a"));
    CHECK(!http_host_is_local("[fd00::1]"));
}

static void test_form(void)
{
    const char *f = "dp=16&v=-25&name=a+b%21&empty=&bad=%4";
    size_t n = strlen(f);
    char out[16];
    CHECK(http_form_get(f, n, "dp", out, sizeof out) && !strcmp(out, "16"));
    CHECK(http_form_get(f, n, "v", out, sizeof out) && !strcmp(out, "-25"));
    CHECK(http_form_get(f, n, "name", out, sizeof out) && !strcmp(out, "a b!"));
    CHECK(http_form_get(f, n, "empty", out, sizeof out) && !strcmp(out, ""));
    CHECK(!http_form_get(f, n, "bad", out, sizeof out));
    CHECK(!http_form_get(f, n, "d", out, sizeof out));
    CHECK(!http_form_get(f, n, "missing", out, sizeof out));
    CHECK(!http_form_get(f, n, "name", out, 4)); /* doesn't fit */
    CHECK(http_form_get(f, 4, "dp", out, sizeof out) && !strcmp(out, "1")); /* length-bounded */
}

int main(void)
{
    RUN(test_get);
    RUN(test_post_headers);
    RUN(test_incomplete_and_malformed);
    RUN(test_host);
    RUN(test_form);
    printf("%d checks, %d failed\n", t_checks, t_fails);
    return t_fails != 0;
}
