/* Loopback client for matter-host: runs the shared test initiator (libs/matter-node/test/mt_test_init.c) over a
 * real UDP socket against a running node.
 *   matter-host-client --port N [--host ::1] [--expect-chunks N]
 * It shares the frame, SPAKE2+ and TLV code with the node, so a pass shows the stack is self-consistent, not that
 * chip-tool or Apple interoperate. The two independent anchors: the PBKDF2 passcode derivation is compared with
 * the verifier matter_setup.py (pure Python) generated for the node, and with a chip-tool PBKDF2 vector.
 * Exit status 0 only if every step passed. */
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "host_cfg.h"
#include "host_port.h"
#include "mt_test_init.h"
#include "setup_info.h"

static int failures;
#define CHECK(c) do { if (!(c)) { failures++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)
#define STEP(s) do { printf("-- %s\n", s); fflush(stdout); } while (0)

static int g_fd;

static void io_send(void *ctx, const uint8_t *f, size_t n) { (void)ctx; send(g_fd, f, n, 0); }
static size_t io_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t wait_ms)
{
    struct pollfd p = { g_fd, POLLIN, 0 };
    ssize_t n;
    (void)ctx;
    if (poll(&p, 1, (int)wait_ms) <= 0) return 0;
    n = recv(g_fd, buf, cap, 0);
    return n > 0 ? (size_t)n : 0;
}

static bool str_is(const ti_attr *a, const char *s) { return a && a->str_len == strlen(s) && !memcmp(a->str, s, a->str_len); }

int main(int argc, char **argv)
{
    const char *host = "::1", *port = NULL;
    unsigned expect_chunks = 0;
    struct addrinfo hints, *res;
    static ti t;
    static ti_report rep;
    uint32_t iters = 0;
    static const uint8_t SALT[] = MATTER_PBKDF_SALT;
    static const uint8_t W0[] = MATTER_SPAKE2P_W0;
    static const uint8_t LPT[] = MATTER_SPAKE2P_L;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) port = argv[++i];
        else if (!strcmp(argv[i], "--host") && i + 1 < argc) host = argv[++i];
        else if (!strcmp(argv[i], "--expect-chunks") && i + 1 < argc) expect_chunks = (unsigned)atoi(argv[++i]);
        else { fprintf(stderr, "usage: %s --port N [--host H] [--expect-chunks N]\n", argv[0]); return 2; }
    }
    if (!port) { fprintf(stderr, "--port is required\n"); return 2; }
    alarm(90); /* a broken node must not hang the test */

    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, port, &hints, &res)) { fprintf(stderr, "cannot resolve %s\n", host); return 2; }
    g_fd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (g_fd < 0 || connect(g_fd, res->ai_addr, res->ai_addrlen)) { perror("connect"); return 2; }
    freeaddrinfo(res);

    ti_io io = { NULL, io_send, io_recv };
    ti_init(&t, io, mh_entropy, NULL);

    STEP("passcode derivation vs matter_setup.py");
    {
        uint8_t w0[32], w1[32], l[65];
        CHECK(ti_passcode_to_w(&t.rng, MATTER_PASSCODE, mt_span_of(SALT, sizeof SALT), MATTER_PBKDF_ITERATIONS, w0, w1, l) == MT_OK);
        CHECK(memcmp(w0, W0, sizeof W0) == 0);
        CHECK(memcmp(l, LPT, sizeof LPT) == 0);
    }

    STEP("wrong passcode must fail");
    CHECK(ti_pase(&t, MATTER_PASSCODE + 1, &iters) == MT_ERR_CRYPTO);
    CHECK(iters == MATTER_PBKDF_ITERATIONS);
    CHECK(!t.secure);

    STEP("wrong cA (Pake3 sent anyway) must be rejected by the node");
    t.force_pake3 = true;
    CHECK(ti_pase(&t, MATTER_PASSCODE + 1, NULL) == MT_ERR_CRYPTO);
    t.force_pake3 = false;
    CHECK(t.status_general == 1 && t.status_code == 2);
    CHECK(!t.secure);

    STEP("right passcode must succeed");
    CHECK(ti_pase(&t, MATTER_PASSCODE, NULL) == MT_OK);
    CHECK(t.secure);
    if (!t.secure) { printf("FAILED (%d)\n", failures); return 1; }

    STEP("read VendorName, ProductID, SoftwareVersion");
    {
        ti_path p[3] = { { 0, 0x28, 1 }, { 0, 0x28, 4 }, { 0, 0x28, 9 } };
        CHECK(ti_read(&t, p, 3, &rep) == MT_OK);
        CHECK(str_is(ti_find(&rep, 0, 0x28, 1), MH_VENDOR_NAME));
        const ti_attr *pid = ti_find(&rep, 0, 0x28, 4), *sw = ti_find(&rep, 0, 0x28, 9);
        CHECK(pid && pid->val == MATTER_PRODUCT_ID);
        CHECK(sw && sw->val == MH_SOFTWARE_VERSION);
    }

    STEP("wildcard read of endpoint 0 (chunked)");
    {
        ti_path p[1] = { { 0, -1, -1 } };
        CHECK(ti_read(&t, p, 1, &rep) == MT_OK);
        printf("   %zu attributes in %u chunks\n", rep.n, rep.chunks);
        CHECK(rep.n > 20 && !rep.overflow);
        CHECK(rep.chunks >= (expect_chunks ? expect_chunks : 1));
        for (size_t i = 0; i < rep.n; i++) CHECK(!rep.a[i].is_status);
        CHECK(str_is(ti_find(&rep, 0, 0x28, 3), MH_PRODUCT_NAME));
        CHECK(ti_find(&rep, 0, 0x1D, 0) || ti_find(&rep, 0, 0x1D, 0xFFFB));
    }

    ti_close_session(&t);
    ti_free(&t);
    close(g_fd);
    if (failures) { printf("FAILED (%d checks)\n", failures); return 1; }
    printf("OK\n");
    return 0;
}
