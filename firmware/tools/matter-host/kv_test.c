/* Host kv store test (make -C tools/matter-host test): mt_kv_ops contract on the file store, including the
 * "finish(apply) is atomic" promise under a crash at every commit step (mh_kv_crash_after). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "host_port.h"

static int failures, checks;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static char dir[256];

static int val_of(const mt_kv_ops *kv, uint16_t key)   /* the one-byte value, -1 = absent, -2 = error */
{
    uint8_t b[4];
    size_t n = 0;
    mt_err e = kv->get(kv->ctx, key, mt_buf_of(b, sizeof b), &n);
    if (e == MT_ERR_NOT_FOUND) return -1;
    return e || n != 1 ? -2 : b[0];
}

static void put(const mt_kv_ops *kv, uint16_t key, uint8_t v) { CHECK(kv->set(kv->ctx, key, mt_span_of(&v, 1)) == MT_OK); }

static void reopen(mt_kv_ops *kv) { CHECK(mh_kv_open(dir, kv) != NULL); }

int main(void)
{
    mt_kv_ops kv;
    uint8_t big[8] = { 0 };
    size_t n;
    snprintf(dir, sizeof dir, "%s/mh-kv-test.%d", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
    reopen(&kv);

    /* basics: absent, staged is invisible until finish, apply, drop, delete, too small */
    CHECK(val_of(&kv, 0x0101) == -1);
    put(&kv, 0x0101, 7);
    CHECK(val_of(&kv, 0x0101) == -1);
    CHECK(kv.finish(kv.ctx, true) == MT_OK);
    CHECK(val_of(&kv, 0x0101) == 7);
    put(&kv, 0x0101, 8);
    CHECK(kv.finish(kv.ctx, false) == MT_OK);
    CHECK(val_of(&kv, 0x0101) == 7);
    CHECK(kv.set(kv.ctx, 0x0102, mt_span_of(big, sizeof big)) == MT_OK && kv.finish(kv.ctx, true) == MT_OK);
    CHECK(kv.get(kv.ctx, 0x0102, mt_buf_of(big, 4), &n) == MT_ERR_BUFFER_TOO_SMALL);
    CHECK(kv.del(kv.ctx, 0x0102) == MT_OK && kv.del(kv.ctx, 0x0999) == MT_OK && kv.finish(kv.ctx, true) == MT_OK);
    CHECK(val_of(&kv, 0x0102) == -1);
    reopen(&kv);
    CHECK(val_of(&kv, 0x0101) == 7);

    /* atomicity: old state {A=1, B=1, C=1}; one commit sets A=2, B=2 and deletes C. A crash at any step
     * must leave all old or all new after reopening. */
    for (int crash = 0; crash < 6; crash++) {
        put(&kv, 0x0201, 1); put(&kv, 0x0202, 1); put(&kv, 0x0203, 1);
        CHECK(kv.finish(kv.ctx, true) == MT_OK);
        put(&kv, 0x0201, 2); put(&kv, 0x0202, 2);
        CHECK(kv.del(kv.ctx, 0x0203) == MT_OK);
        mh_kv_crash_after = crash;
        mt_err e = kv.finish(kv.ctx, true);
        mh_kv_crash_after = -1;
        reopen(&kv);                                  /* the "reboot" */
        int a = val_of(&kv, 0x0201), b = val_of(&kv, 0x0202), c = val_of(&kv, 0x0203);
        bool old = a == 1 && b == 1 && c == 1, neu = a == 2 && b == 2 && c == -1;
        if (!(old || neu)) printf("  crash after %d steps: A=%d B=%d C=%d\n", crash, a, b, c);
        CHECK(old || neu);
        CHECK(e != MT_OK || neu);                     /* a reported success is durable */
        CHECK(val_of(&kv, 0x0101) == 7);              /* untouched keys survive */
    }

    /* a damaged tail (a record running past the end) is an error, never "end of file": reads fail and a commit
     * refuses to rewrite the image without it */
    char path[300];
    snprintf(path, sizeof path, "%s/kv.bin", dir);
    FILE *f = fopen(path, "ab");
    CHECK(f && fwrite("\x01\x03\x40\x00", 1, 4, f) == 4 && !fclose(f));
    reopen(&kv);
    CHECK(val_of(&kv, 0x0101) == -2);
    put(&kv, 0x0301, 5);
    CHECK(kv.finish(kv.ctx, true) == MT_ERR_IO);
    f = fopen(path, "rb");
    CHECK(f && !fseek(f, 0, SEEK_END) && ftell(f) > 4);
    if (f) fclose(f);
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    if (system(cmd)) {}
    printf("host kv: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
