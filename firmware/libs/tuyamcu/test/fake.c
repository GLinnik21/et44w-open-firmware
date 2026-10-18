#include "fake.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static int w(void *ctx, const uint8_t *b, size_t n)
{
    fake *f = ctx;
    tm_parser p;
    uint8_t buf[256];
    tm_parser_init(&p, buf, sizeof buf);
    bool got = false;
    for (size_t i = 0; i < n; i++) got = tm_parser_feed(&p, b[i]) || got; /* must be 1 valid frame */
    if (!got || f->ntx >= MAX_TX) abort();
    f->tx_ver[f->ntx] = p.frame.ver;
    f->tx_cmd[f->ntx] = p.frame.cmd;
    f->tx_len[f->ntx] = p.frame.len;
    if (p.frame.len > 64) abort();
    memcpy(f->tx_data[f->ntx], p.frame.data, p.frame.len);
    f->ntx++;
    return (int)n;
}

static uint32_t now(void *ctx) { return ((fake *)ctx)->now; }

static bool get_time(void *ctx, bool local, tm_time *t)
{
    fake *f = ctx;
    (void)local;
    if (!f->time_known) return false;
    *t = f->time;
    return true;
}

static void logf_(void *ctx, const char *fmt, ...)
{
    (void)ctx;
    (void)fmt;
}

static void on_event(void *ctx, const tm_event *ev)
{
    fake *f = ctx;
    if (f->nev >= MAX_EV) abort();
    int i = f->nev++;
    f->ev_type[i] = ev->type;
    f->ev_arg[i] = ev->arg;
    if (ev->type == TM_EV_DP) {
        f->ev_dpid[i] = ev->dp->id;
        f->ev_dptype[i] = ev->dp->type;
        f->ev_u32[i] = tm_dp_u32(ev->dp);
    }
}

static void on_frame(void *ctx, bool tx, const tm_frame *fr)
{
    fake *f = ctx;
    if (f->nframe >= MAX_FRAME) abort();
    f->frame_tx[f->nframe] = tx;
    f->frame_cmd[f->nframe] = fr->cmd;
    f->frame_len[f->nframe] = fr->len;
    f->nframe++;
}

void fake_init(fake *f)
{
    memset(f, 0, sizeof *f);
    tuyamcu_io io = {f, w, now, get_time, logf_, on_event, on_frame};
    tuyamcu_init(&f->tm, &io);
}

void fake_inject(fake *f, uint8_t ver, uint8_t cmd, const uint8_t *data, size_t len)
{
    uint8_t buf[300];
    size_t n = tm_frame_build(buf, sizeof buf, ver, cmd, data, len);
    tuyamcu_rx(&f->tm, buf, n);
}

void fake_clear(fake *f)
{
    f->ntx = 0;
    f->nev = 0;
    f->nframe = 0;
}

void fake_link_up(fake *f)
{
    uint8_t zero = 0;
    tuyamcu_poll(&f->tm);                              /* heartbeat query */
    fake_inject(f, 3, TM_CMD_HEARTBEAT, &zero, 1);     /* MCU: first heartbeat */
    fake_inject(f, 3, TM_CMD_PRODUCT, (const uint8_t *)"{}", 2);
    fake_inject(f, 3, TM_CMD_MODE, NULL, 0);
    fake_clear(f);
}

int fake_count_cmd(const fake *f, uint8_t cmd)
{
    int c = 0;
    for (int i = 0; i < f->ntx; i++) c += f->tx_cmd[i] == cmd;
    return c;
}
