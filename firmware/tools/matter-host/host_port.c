/* POSIX ports, see host_port.h. */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "host_port.h"

uint32_t mh_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
}

int mh_entropy(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    int fd = open("/dev/urandom", O_RDONLY);
    size_t got = 0;
    if (fd < 0) return -1;
    while (got < len) {
        ssize_t r = read(fd, out + got, len - got);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

/* ---- UDP ---- */
static bool g_v6;

/* Not inherited by the dns-sd children: a crashed node must not leave its port bound by them. */
static int udp_socket(int family)
{
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int mh_udp_open(uint16_t port, uint16_t *bound_port)
{
    int fd = udp_socket(AF_INET6);
    if (fd >= 0) {
        struct sockaddr_in6 a;
        int off = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
        memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_any;
        a.sin6_port = htons(port);
        if (bind(fd, (struct sockaddr *)&a, sizeof a) == 0) {
            socklen_t l = sizeof a;
            getsockname(fd, (struct sockaddr *)&a, &l);
            *bound_port = ntohs(a.sin6_port);
            g_v6 = true;
            return fd;
        }
        close(fd);
    }
    fd = udp_socket(AF_INET);
    if (fd >= 0) {
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        a.sin_port = htons(port);
        if (bind(fd, (struct sockaddr *)&a, sizeof a) == 0) {
            socklen_t l = sizeof a;
            getsockname(fd, (struct sockaddr *)&a, &l);
            *bound_port = ntohs(a.sin_port);
            g_v6 = false;
            return fd;
        }
        close(fd);
    }
    return -1;
}

void mh_udp_send(int fd, const mt_node_addr *to, mt_span frame)
{
    if (g_v6) {
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        memcpy(&a.sin6_addr, to->ip, 16);
        a.sin6_scope_id = to->scope;
        a.sin6_port = htons(to->port);
        sendto(fd, frame.p, frame.len, 0, (struct sockaddr *)&a, sizeof a);
    } else {
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        memcpy(&a.sin_addr, to->ip, 4);
        a.sin_port = htons(to->port);
        sendto(fd, frame.p, frame.len, 0, (struct sockaddr *)&a, sizeof a);
    }
}

long mh_udp_recv(int fd, mt_node_addr *from, uint8_t *buf, size_t cap)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    ssize_t n = recvfrom(fd, buf, cap, MSG_DONTWAIT, (struct sockaddr *)&ss, &sl);
    if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
    memset(from, 0, sizeof *from);
    if (ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)&ss;
        memcpy(from->ip, &a->sin6_addr, 16);
        from->scope = a->sin6_scope_id;
        from->port = ntohs(a->sin6_port);
        from->family = 6;
    } else {
        const struct sockaddr_in *a = (const struct sockaddr_in *)&ss;
        memcpy(from->ip, &a->sin_addr, 4);
        from->port = ntohs(a->sin_port);
        from->family = 4;
    }
    return (long)n;
}

/* ---- kv ----
 * One file, <dir>/kv.bin, holding every record as [key u16 LE][len u16 LE][value]. finish(apply) writes the
 * merged image to kv.bin.tmp, fsyncs it, renames it over kv.bin and fsyncs the directory: the rename is the
 * single commit point, so a crash leaves either the old or the new image, never a mix. */
#define KV_STAGE 16
#define KV_MAX 1024
#define KV_FILE_MAX (64 * 1024)

typedef struct { uint16_t key; bool del; size_t len; uint8_t data[KV_MAX]; } staged;
struct mh_kv {
    char dir[512];
    staged st[KV_STAGE];
    size_t n;
};

static uint8_t kv_img[KV_FILE_MAX], kv_new[KV_FILE_MAX];

int mh_kv_crash_after = -1;

static bool crash_now(void) { return mh_kv_crash_after >= 0 && mh_kv_crash_after-- == 0; }

static void kv_path(const mh_kv *k, const char *name, char *out, size_t cap) { snprintf(out, cap, "%s/%s", k->dir, name); }

static size_t kv_next(const uint8_t *img, size_t len, size_t off, uint16_t *key, mt_span *val);

/* Reads the committed image; 0 bytes if there is none yet. An image whose records do not end exactly at its end
 * (truncated or corrupt) is MT_ERR_IO: reads fail and no commit rewrites it without the damaged tail. */
static mt_err kv_load(const mh_kv *k, uint8_t *img, size_t *len)
{
    char path[600];
    FILE *f;
    kv_path(k, "kv.bin", path, sizeof path);
    *len = 0;
    f = fopen(path, "rb");
    if (!f) return errno == ENOENT ? MT_OK : MT_ERR_IO;
    *len = fread(img, 1, KV_FILE_MAX, f);
    bool bad = ferror(f) || fgetc(f) != EOF;
    fclose(f);
    if (bad) return MT_ERR_IO;
    size_t off = 0, end = 0;
    uint16_t kk;
    mt_span v;
    while ((off = kv_next(img, *len, off, &kk, &v)) != 0) end = off;
    return end == *len ? MT_OK : MT_ERR_IO;
}

/* Walks the records of an image: returns the offset after record i, or 0 at the end / on a malformed tail
 * (kv_load has already refused an image with one). */
static size_t kv_next(const uint8_t *img, size_t len, size_t off, uint16_t *key, mt_span *val)
{
    if (off + 4 > len) return 0;
    size_t vl = mt_get_le16(img + off + 2);
    if (off + 4 + vl > len) return 0;
    *key = mt_get_le16(img + off);
    *val = mt_span_of(img + off + 4, vl);
    return off + 4 + vl;
}

static mt_err kv_get(void *ctx, uint16_t key, mt_buf out, size_t *len)
{
    mh_kv *k = ctx;
    size_t il, off = 0;
    uint16_t kk;
    mt_span v;
    if (kv_load(k, kv_img, &il)) return MT_ERR_IO;
    while ((off = kv_next(kv_img, il, off, &kk, &v)) != 0) {
        if (kk != key) continue;
        if (v.len > out.cap) return MT_ERR_BUFFER_TOO_SMALL;
        memcpy(out.p, v.p, v.len);
        *len = v.len;
        return MT_OK;
    }
    return MT_ERR_NOT_FOUND;
}

static staged *stage_slot(mh_kv *k, uint16_t key)
{
    for (size_t i = 0; i < k->n; i++) if (k->st[i].key == key) return &k->st[i];
    return k->n < KV_STAGE ? &k->st[k->n++] : NULL;
}

static mt_err kv_set(void *ctx, uint16_t key, mt_span val)
{
    mh_kv *k = ctx;
    staged *s;
    if (val.len > KV_MAX) return MT_ERR_BUFFER_TOO_SMALL;
    s = stage_slot(k, key);
    if (!s) return MT_ERR_IO;
    s->key = key;
    s->del = false;
    s->len = val.len;
    memcpy(s->data, val.p, val.len);
    return MT_OK;
}

static mt_err kv_del(void *ctx, uint16_t key)
{
    mh_kv *k = ctx;
    staged *s = stage_slot(k, key);
    if (!s) return MT_ERR_IO;
    s->key = key;
    s->del = true;
    s->len = 0;
    return MT_OK;
}

static bool kv_append(size_t *nl, uint16_t key, const uint8_t *p, size_t len)
{
    if (*nl + 4 + len > KV_FILE_MAX) return false;
    mt_put_le16(kv_new + *nl, key);
    mt_put_le16(kv_new + *nl + 2, (uint16_t)len);
    memcpy(kv_new + *nl + 4, p, len);
    *nl += 4 + len;
    return true;
}

static int fsync_dir(const char *dir)
{
    int fd = open(dir, O_RDONLY), r;
    if (fd < 0) return -1;
    r = fsync(fd);
    close(fd);
    return r;
}

static mt_err kv_finish(void *ctx, bool apply)
{
    mh_kv *k = ctx;
    char tmp[600], dst[600];
    size_t n = k->n, il, nl = 0, off = 0;
    uint16_t kk;
    mt_span v;
    FILE *f;
    bool ok;
    k->n = 0;
    if (!apply || n == 0) return MT_OK;
    if (kv_load(k, kv_img, &il)) return MT_ERR_IO;
    while ((off = kv_next(kv_img, il, off, &kk, &v)) != 0) {   /* records nobody touched */
        bool staged_key = false;
        for (size_t i = 0; i < n; i++) staged_key |= k->st[i].key == kk;
        if (!staged_key && !kv_append(&nl, kk, v.p, v.len)) return MT_ERR_IO;
    }
    for (size_t i = 0; i < n; i++)
        if (!k->st[i].del && !kv_append(&nl, k->st[i].key, k->st[i].data, k->st[i].len)) return MT_ERR_IO;
    kv_path(k, "kv.bin.tmp", tmp, sizeof tmp);
    kv_path(k, "kv.bin", dst, sizeof dst);
    f = fopen(tmp, "wb");
    if (!f) return MT_ERR_IO;
    ok = fwrite(kv_new, 1, nl, f) == nl;
    ok = !fflush(f) && !fsync(fileno(f)) && ok;
    ok = !fclose(f) && ok;
    if (!ok) { unlink(tmp); return MT_ERR_IO; }
    if (crash_now()) return MT_ERR_IO;                         /* dies before the commit point */
    if (rename(tmp, dst)) { unlink(tmp); return MT_ERR_IO; }  /* the commit point */
    if (crash_now()) return MT_ERR_IO;                         /* dies after it */
    /* Committed: the caller must not roll back. A failed directory sync only weakens durability over a host
     * crash, so it is reported here and not as a failed commit. */
    if (fsync_dir(k->dir)) fprintf(stderr, "kv: directory sync failed after commit\n");
    return MT_OK;
}

mh_kv *mh_kv_open(const char *dir, mt_kv_ops *ops_out)
{
    static mh_kv kv;
    char tmp[600];
    memset(&kv, 0, sizeof kv);
    if (strlen(dir) >= sizeof kv.dir) return NULL;
    strcpy(kv.dir, dir);
    if (mkdir(dir, 0700) && errno != EEXIST) return NULL;
    kv_path(&kv, "kv.bin.tmp", tmp, sizeof tmp);
    unlink(tmp);                                               /* an uncommitted image from a crash */
    ops_out->ctx = &kv;
    ops_out->get = kv_get;
    ops_out->set = kv_set;
    ops_out->del = kv_del;
    ops_out->finish = kv_finish;
    return &kv;
}
