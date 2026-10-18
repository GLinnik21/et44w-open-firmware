/* dns-sd children, see host_mdns.h. Service types with subtypes are comma-joined, as dns-sd -R expects:
 *   dns-sd -R <instance> _matterc._udp,_L3840,_S15,_V65521,_CM local <port> D=3840 CM=1 ...
 * mDNSResponder renames an instance on a conflict ("<name> (2)"); the child log shows that. */
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "host_mdns.h"

extern char **environ;

typedef struct {
    pid_t pid;
    char key[1024];   /* the full argument list, joined: equal key = same registration */
} child;

static child g_ch[MT_NODE_MDNS_MAX];
static uint16_t g_port;
static const char *g_log_dir;

void mh_mdns_init(uint16_t port, const char *log_dir)
{
    g_port = port;
    g_log_dir = log_dir;
    memset(g_ch, 0, sizeof g_ch);
}

static void kill_child(child *c)
{
    if (c->pid > 0) {
        kill(c->pid, SIGTERM);
        waitpid(c->pid, NULL, 0);
    }
    c->pid = 0;
    c->key[0] = 0;
}

/* argv for one record; strings live in `store`. Returns argc. */
static int build_argv(const mt_node_mdns_rec *r, char store[24][64], char *argv[26])
{
    int a = 0, s = 0;
    size_t off;
    argv[a++] = "dns-sd";
    argv[a++] = "-R";
    snprintf(store[s], 64, "%s", r->instance);
    argv[a++] = store[s++];
    off = (size_t)snprintf(store[s], 64, "%s", r->operational ? "_matter._tcp" : "_matterc._udp");
    for (unsigned i = 0; i < r->n_sub && off < 64; i++) off += (size_t)snprintf(store[s] + off, 64 - off, ",%s", r->sub[i]);
    argv[a++] = store[s++];
    argv[a++] = "local";
    snprintf(store[s], 64, "%u", g_port);
    argv[a++] = store[s++];
    for (unsigned i = 0; i < r->n_txt && s < 24; i++) {
        snprintf(store[s], 64, "%s", r->txt[i]);
        argv[a++] = store[s++];
    }
    argv[a] = NULL;
    return a;
}

static pid_t spawn(char *argv[], unsigned slot)
{
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t at;
    char log[512];
    pid_t pid = 0;
    if (g_log_dir) snprintf(log, sizeof log, "%s/mdns-%u.log", g_log_dir, slot);
    else snprintf(log, sizeof log, "/dev/null");
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 1, log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    posix_spawn_file_actions_adddup2(&fa, 1, 2);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawnattr_init(&at);
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    /* the child gets only the descriptors opened above (the node's sockets and files stay with the node) */
    posix_spawnattr_setflags(&at, POSIX_SPAWN_CLOEXEC_DEFAULT);
#endif
    if (posix_spawnp(&pid, "dns-sd", &fa, &at, argv, environ) != 0) pid = 0;
    posix_spawnattr_destroy(&at);
    posix_spawn_file_actions_destroy(&fa);
    return pid;
}

void mh_mdns_sync(const mt_node *n)
{
    char want[MT_NODE_MDNS_MAX][1024];
    char *argvs[MT_NODE_MDNS_MAX][26];
    static char store[MT_NODE_MDNS_MAX][24][64];
    unsigned cnt = mt_node_mdns_count(n);
    bool kept[MT_NODE_MDNS_MAX] = { false };
    if (cnt > MT_NODE_MDNS_MAX) cnt = MT_NODE_MDNS_MAX;

    for (unsigned i = 0; i < cnt; i++) {
        mt_node_mdns_rec r;
        size_t off = 0;
        want[i][0] = 0;
        if (!mt_node_mdns_get(n, i, &r)) { cnt = i; break; }
        int argc = build_argv(&r, store[i], argvs[i]);
        for (int k = 0; k < argc && off < sizeof want[i]; k++)
            off += (size_t)snprintf(want[i] + off, sizeof want[i] - off, "%s ", argvs[i][k]);
    }
    /* reap children that died on their own, withdraw records that went away or changed */
    for (unsigned c = 0; c < MT_NODE_MDNS_MAX; c++) {
        bool live = false;
        if (g_ch[c].pid > 0 && waitpid(g_ch[c].pid, NULL, WNOHANG) == g_ch[c].pid) { g_ch[c].pid = 0; g_ch[c].key[0] = 0; }
        if (!g_ch[c].pid) continue;
        for (unsigned i = 0; i < cnt; i++)
            if (!kept[i] && !strcmp(g_ch[c].key, want[i])) { kept[i] = live = true; break; }
        if (!live) {
            printf("mdns: withdraw %s\n", g_ch[c].key);
            kill_child(&g_ch[c]);
        }
    }
    for (unsigned i = 0; i < cnt; i++) {
        if (kept[i]) continue;
        for (unsigned c = 0; c < MT_NODE_MDNS_MAX; c++) {
            if (g_ch[c].pid) continue;
            g_ch[c].pid = spawn(argvs[i], c);
            snprintf(g_ch[c].key, sizeof g_ch[c].key, "%s", want[i]);
            printf("mdns: register %s(pid %d)\n", want[i], (int)g_ch[c].pid);
            break;
        }
    }
    fflush(stdout);
}

void mh_mdns_stop(void)
{
    for (unsigned c = 0; c < MT_NODE_MDNS_MAX; c++) kill_child(&g_ch[c]);
}
