/* matter-host: the Matter node stack on the Mac over real UDP: endpoint 0 (commissioning, fabrics, ACL, ...) and
 * a simulated thermostat on endpoint 1 (libs/matter-thermostat on libs/thermo, host_sim.c).
 *   matter-host [--port N] [--kv-dir DIR] [--reset] [--im-buf BYTES] [--no-mdns] [--window S]
 *     --kv-dir   persistent state (fabrics, BOOT record, ...); default ./matter-host-kv
 *     --reset    wipe the kv dir first (factory reset)
 *     --no-mdns  do not register dns-sd records (loopback tests)
 * Prints the setup codes, then "PORT=<n>" once the socket is bound. Signals: SIGUSR1 raises the simulated room
 * temperature by 0.5 C, SIGUSR2 lowers it by 0.5 C; SIGINT/SIGTERM stop (dns-sd children are killed).
 * Attestation: the public connectedhomeip test DAC/PAI/CD (test_credentials.c) - controllers show the device as
 * uncertified. */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "banner.h"
#include "host_cfg.h"
#include "host_mdns.h"
#include "host_port.h"
#include "host_sim.h"
#include "setup_info.h"
#include "test_credentials.h"

static int g_fd = -1;
/* Written only by the handlers; the main loop reads them and keeps its own count of what it has applied, so a
 * signal arriving mid-loop is never lost. A handler is not re-entered by its own signal (BSD signal semantics). */
static volatile sig_atomic_t g_stop, g_ups, g_downs;
static bool g_mdns_dirty;
static mt_rng g_sign_rng;

static void on_signal(int s) { (void)s; g_stop = 1; }
static void on_usr1(int s) { (void)s; g_ups = (sig_atomic_t)(g_ups + 1); }
static void on_usr2(int s) { (void)s; g_downs = (sig_atomic_t)(g_downs + 1); }
static uint32_t p_now(void *c) { (void)c; return mh_now_ms(); }
static void p_send(void *c, const mt_node_addr *to, mt_span f) { (void)c; mh_udp_send(g_fd, to, f); }
static void p_mdns_changed(void *c) { (void)c; g_mdns_dirty = true; }
static void p_utc_set(void *c, uint64_t matter_us, uint8_t gran, uint8_t src)
{
    (void)c;
    printf("utc_set: matter_us=%llu granularity=%u source=%u\n", (unsigned long long)matter_us, gran, src);
    fflush(stdout);
}

static mt_err dac_sign(void *c, mt_span msg, uint8_t sig[MT_P256_SIG_LEN])
{
    (void)c;
    return mt_crypto_p256_sign(&g_sign_rng, mh_test_creds.dac_priv, msg, sig);
}

static const uint8_t SALT[] = MATTER_PBKDF_SALT;
static const uint8_t W0[] = MATTER_SPAKE2P_W0;
static const uint8_t LPT[] = MATTER_SPAKE2P_L;

static const mt_basic_cfg BASIC = {
    MH_VENDOR_NAME, MATTER_VENDOR_ID, MH_PRODUCT_NAME, MATTER_PRODUCT_ID, 1, "1", MH_SOFTWARE_VERSION, "1.0.0",
    "HOST-0001", "matter-host-0001", 3, 3, 1,
};

static void wipe_kv(const char *dir)
{
    char p[1024];
    snprintf(p, sizeof p, "%s/kv.bin", dir);
    if (unlink(p) && errno != ENOENT) perror(p);
    snprintf(p, sizeof p, "%s/kv.bin.tmp", dir);
    (void)unlink(p);
}

int main(int argc, char **argv)
{
    uint16_t port = 5540, bound = 0;
    const char *kv_dir = "matter-host-kv";
    unsigned im_buf = 0;
    uint32_t window_s = 900;              /* like the device: a public test passcode must not stay open */
    bool reset = false, mdns = true;
    static mt_node node;
    static mh_sim sim;
    mt_node_credentials cred;
    mt_node_cfg cfg;
    mt_kv_ops kv;
    uint8_t buf[2048];

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) port = (uint16_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--kv-dir") && i + 1 < argc) kv_dir = argv[++i];
        else if (!strcmp(argv[i], "--im-buf") && i + 1 < argc) im_buf = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--window") && i + 1 < argc) window_s = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--reset")) reset = true;
        else if (!strcmp(argv[i], "--no-mdns")) mdns = false;
        else {
            fprintf(stderr, "usage: %s [--port N] [--kv-dir DIR] [--reset] [--im-buf BYTES] [--no-mdns] [--window S, default 900, 0 = until commissioned]\n",
                    argv[0]);
            return 2;
        }
    }
    if (mt_rng_init(&g_sign_rng, mh_entropy, NULL) != MT_OK) { fprintf(stderr, "rng\n"); return 1; }

    memset(&cred, 0, sizeof cred);
    memcpy(cred.w0, W0, sizeof W0);
    memcpy(cred.l, LPT, sizeof LPT);
    cred.salt = mt_span_of(SALT, sizeof SALT);
    cred.iterations = MATTER_PBKDF_ITERATIONS;
    cred.discriminator = MATTER_DISCRIMINATOR;
    cred.attest.dac = mh_test_creds.dac;
    cred.attest.pai = mh_test_creds.pai;
    cred.attest.cd = mh_test_creds.cd;
    cred.attest.vendor_id = mh_test_creds.vid;
    cred.attest.product_id = mh_test_creds.pid;
    cred.attest.sign = dac_sign;

    mkdir(kv_dir, 0700);
    if (reset) wipe_kv(kv_dir);
    if (!mh_kv_open(kv_dir, &kv)) { perror("kv dir"); return 1; }

    if (mh_sim_init(&sim, mh_now_ms()) != MT_OK) { fprintf(stderr, "thermostat init failed\n"); return 1; }

    g_fd = mh_udp_open(port, &bound);
    if (g_fd < 0) { perror("udp"); return 1; }
    fprintf(stderr, "warning: test node on all interfaces with the public test passcode; anyone on this LAN can "
                    "commission it while the window is open (%s)\n", window_s ? "--window" : "until commissioned");

    memset(&cfg, 0, sizeof cfg);
    cfg.ports.now_ms = p_now;
    cfg.ports.udp_send = p_send;
    cfg.ports.entropy = mh_entropy;
    cfg.ports.cred = &cred;
    cfg.ports.kv = &kv;
    cfg.ports.mdns_changed = p_mdns_changed;
    cfg.ports.utc_set = p_utc_set;
    cfg.basic = &BASIC;
    cfg.im_buf_len = (uint16_t)im_buf;
    cfg.extra_eps = mt_thermostat_endpoint(&sim.ts);
    cfg.n_extra_eps = mt_thermostat_endpoint_count(&sim.ts);
    cfg.boot_window_s = window_s;
    cfg.boot_reason = MT_BOOT_POWER_ON;
    cfg.device_type = MT_THERMOSTAT_DEVICE_TYPE;
    cfg.device_name = MH_PRODUCT_NAME;
    cfg.pairing_hint = 33;                /* power cycle + device manual (chip's default) */
    cfg.location_cap = MT_REG_INDOOR_OUTDOOR;
    if (mt_node_init(&node, &cfg) != MT_OK) { fprintf(stderr, "node init failed\n"); return 1; }
    sim.dm = &node.dm;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP, on_signal);
    signal(SIGUSR1, on_usr1);
    signal(SIGUSR2, on_usr2);
    signal(SIGPIPE, SIG_IGN);
    if (mdns) mh_mdns_init(bound, kv_dir);
    fputs(MH_BANNER, stdout);
    printf("fabrics=%u reboot_count=%u window=%s\n", mt_fabric_committed_count(&node.fabrics),
           mt_node_reboot_count(&node), mt_node_window_open(&node) ? "open" : "closed");
    printf("PORT=%u\n", bound);
    fflush(stdout);
    g_mdns_dirty = true;

    sig_atomic_t ups = 0, downs = 0;   /* signals applied so far */
    while (!g_stop) {
        uint32_t wait, t;
        sig_atomic_t u = g_ups, d = g_downs;
        if (u != ups || d != downs) {
            int32_t b = 5 * (int32_t)(unsigned)(u - ups) - 5 * (int32_t)(unsigned)(d - downs);
            ups = u;
            downs = d;
            if (b) mh_sim_bump(&sim, b, mh_now_ms());
        }
        wait = mt_node_poll(&node);
        t = mh_sim_poll(&sim, mh_now_ms());
        if (t < wait) wait = t;
        if (g_mdns_dirty) {
            bool open = mt_node_window_open(&node);
            g_mdns_dirty = false;
            printf("state: fabrics=%u (+%u pending) window=%s\n", mt_fabric_committed_count(&node.fabrics),
                   mt_fabric_count(&node.fabrics) - mt_fabric_committed_count(&node.fabrics), open ? "open" : "closed");
            fflush(stdout);
            if (mdns) mh_mdns_sync(&node);
        }
        struct pollfd p = { g_fd, POLLIN, 0 };
        int r = poll(&p, 1, wait > 1000 ? 1000 : (int)wait);
        if (r > 0 && (p.revents & POLLIN)) {
            mt_node_addr from;
            long n;
            while ((n = mh_udp_recv(g_fd, &from, buf, sizeof buf)) > 0) mt_node_on_udp(&node, &from, buf, (size_t)n);
        }
    }
    if (mdns) mh_mdns_stop();
    close(g_fd);
    printf("stopped\n");
    return 0;
}
