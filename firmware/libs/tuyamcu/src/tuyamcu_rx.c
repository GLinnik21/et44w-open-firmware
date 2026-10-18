/* Dispatch of valid MCU -> module frames. */
#include "tm_priv.h"

static void on_dp(void *ctx, const tm_dp *dp)
{
    tm_event ev = {TM_EV_DP, dp, NULL, 0, 0};
    tm_emit((tuyamcu *)ctx, &ev);
}

static void on_heartbeat(tuyamcu *tm, const tm_frame *f)
{
    if (f->len == 0) { /* MCU-initiated: 0 on our first answer, 1 afterwards */
        uint8_t v = tm->hb_answered_once ? 1 : 0;
        tm->hb_answered_once = true;
        tm_tx(tm, TM_CMD_HEARTBEAT, &v, 1);
        return;
    }
    bool restarted = f->data[0] == 0;
    if (!tm->link_up) {
        tm->link_up = true;
        tm_event ev = {TM_EV_LINK_UP, NULL, NULL, 0, 0};
        tm_emit(tm, &ev);
        tm_start_init(tm);
    } else if (restarted) {
        TM_LOG(tm, "tuyamcu: MCU restarted, re-initialising");
        tm_start_init(tm);
    }
}

static void on_product(tuyamcu *tm, const tm_frame *f)
{
    tm_event ev = {TM_EV_PRODUCT, NULL, f->data, f->len, 0};
    tm_emit(tm, &ev);
    if (tm->stage == ST_PRODUCT) {
        tm->stage = ST_MODE;
        tm->stage_tx = tm->io.now_ms(tm->io.ctx);
        tm_tx(tm, TM_CMD_MODE, NULL, 0);
    }
}

/* Reply length 0 = module handles the Wi-Fi LED/button; 2 = MCU does (pin numbers). */
static void on_mode(tuyamcu *tm, const tm_frame *f)
{
    if (tm->stage != ST_MODE) return;
    tm->mcu_handles_net = f->len >= 2;
    tm->stage = ST_READY;
    if (!tm->mcu_handles_net) tm_push_net_status(tm);
    tm_tx(tm, TM_CMD_QUERY, NULL, 0);
}

static void on_wifi_reset(tuyamcu *tm, const tm_frame *f)
{
    uint8_t arg = TM_RESET_PLAIN;
    if (f->cmd == TM_CMD_WIFI_MODE && f->len >= 1) arg = f->data[0];
    tm_tx(tm, f->cmd, NULL, 0); /* ack */
    tm_event ev = {TM_EV_WIFI_RESET, NULL, NULL, 0, arg};
    tm_emit(tm, &ev);
}

static void on_time(tuyamcu *tm, const tm_frame *f)
{
    bool local = f->cmd == TM_CMD_TIME_LOCAL;
    tm_time t;
    uint8_t out[TM_TIME_MAX_LEN];
    bool ok = tm->io.get_time && tm->io.get_time(tm->io.ctx, local, &t);
    size_t n = tm_time_encode(out, local, ok ? &t : NULL);
    tm_tx(tm, f->cmd, out, n);
}

void tm_dispatch(tuyamcu *tm, const tm_frame *f)
{
    tm->mcu_ver = f->ver;
    switch (f->cmd) {
    case TM_CMD_HEARTBEAT:
        on_heartbeat(tm, f);
        break;
    case TM_CMD_PRODUCT:
        on_product(tm, f);
        break;
    case TM_CMD_MODE:
        on_mode(tm, f);
        break;
    case TM_CMD_NET_REPORT: /* the MCU's ack of our report: nothing to do */
        break;
    case TM_CMD_NET_QUERY:
        tm_answer_net_query(tm);
        break;
    case TM_CMD_WIFI_RESET:
    case TM_CMD_WIFI_MODE:
        on_wifi_reset(tm, f);
        break;
    case TM_CMD_DP_REPORT:
        if (tm_dp_decode(f->data, f->len, on_dp, tm) < 0) TM_LOG(tm, "tuyamcu: truncated DP report");
        break;
    case TM_CMD_TIME_LOCAL:
    case TM_CMD_TIME_GMT:
        on_time(tm, f);
        break;
    case TM_CMD_TEST:
        break;
    case TM_CMD_OTA_START:
    case TM_CMD_OTA_DATA:
        TM_LOG(tm, "tuyamcu: ignoring MCU OTA cmd 0x%02x", f->cmd);
        break;
    default:
        TM_LOG(tm, "tuyamcu: unhandled cmd 0x%02x ver=%u len=%u", f->cmd, f->ver, f->len);
        break;
    }
}
