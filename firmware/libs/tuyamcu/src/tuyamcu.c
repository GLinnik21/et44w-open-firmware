#include <string.h>

#include "tm_allow.h"
#include "tm_priv.h"

tm_err tm_tx(tuyamcu *tm, uint8_t cmd, const uint8_t *data, size_t len)
{
    size_t n = tm_frame_build(tm->tx, sizeof tm->tx, 0x00, cmd, data, len);
    if (!n) return TM_ERR_ARG;
    if (tm->io.on_frame) {
        tm_frame f = {0x00, cmd, data, (uint16_t)len};
        tm->io.on_frame(tm->io.ctx, true, &f);
    }
    if (tm->io.write(tm->io.ctx, tm->tx, n) < 0) return TM_ERR_IO;
    tm->stats.tx_frames++;
    return TM_OK;
}

void tm_emit(tuyamcu *tm, const tm_event *ev)
{
    if (tm->io.on_event) tm->io.on_event(tm->io.ctx, ev);
}

static void emit_simple(tuyamcu *tm, tm_event_type type)
{
    tm_event ev = {type, NULL, NULL, 0, 0};
    tm_emit(tm, &ev);
}

void tm_start_init(tuyamcu *tm)
{
    tm->stage = ST_PRODUCT;
    tm->stage_tx = tm->io.now_ms(tm->io.ctx);
    tm_tx(tm, TM_CMD_PRODUCT, NULL, 0);
}

/* As the stock module does (Ghidra, FUN_9b01c000): MCU protocol ver < 3 has no "cloud" state, so
 * paired is reported as 0x03 there. */
static uint8_t net_code(const tuyamcu *tm)
{
    return tm->mcu_ver < 3 && tm->net_status == TM_NET_PAIRED ? TM_NET_UNPAIRED : tm->net_status;
}

void tm_push_net_status(tuyamcu *tm)
{
    uint8_t s = net_code(tm);
    tm_tx(tm, TM_CMD_NET_REPORT, &s, 1);
}

void tm_answer_net_query(tuyamcu *tm)
{
    tm_tx(tm, TM_CMD_NET_QUERY, &tm->net_status, 1); /* stock answers 0x2B without the ver < 3 mapping */
}

void tuyamcu_init(tuyamcu *tm, const tuyamcu_io *io)
{
    memset(tm, 0, sizeof *tm);
    tm->io = *io;
    tm->net_status = TM_NET_NO_LINK;
    tm->mcu_ver = 3;
    tm_parser_init(&tm->parser, tm->rx, sizeof tm->rx);
}

void tuyamcu_link_reset(tuyamcu *tm)
{
    tm_parser_init(&tm->parser, tm->rx, sizeof tm->rx);
    tm->stage = ST_DOWN;
    tm->link_up = false;
    tm->hb_sent = false;
}

void tuyamcu_rx(tuyamcu *tm, const uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        for (bool got = tm_parser_feed(&tm->parser, buf[i]); got; got = tm_parser_next(&tm->parser)) {
            tm->stats.frames_ok++;
            tm->last_rx = tm->io.now_ms(tm->io.ctx);
            if (tm->io.on_frame) tm->io.on_frame(tm->io.ctx, false, &tm->parser.frame);
            tm_dispatch(tm, &tm->parser.frame);
        }
    }
}

void tuyamcu_poll(tuyamcu *tm)
{
    uint32_t now = tm->io.now_ms(tm->io.ctx);

    if (tm->link_up && now - tm->last_rx >= TUYAMCU_LINK_TIMEOUT_MS) {
        TM_LOG(tm, "tuyamcu link lost");
        tm->link_up = false;
        tm->stage = ST_DOWN;
        emit_simple(tm, TM_EV_LINK_DOWN);
    }

    uint32_t period = tm->link_up ? TUYAMCU_HB_UP_MS : TUYAMCU_HB_DOWN_MS;
    if (!tm->hb_sent || now - tm->last_hb >= period) {
        tm->hb_sent = true;
        tm->last_hb = now;
        tm_tx(tm, TM_CMD_HEARTBEAT, NULL, 0);
    }

    if ((tm->stage == ST_PRODUCT || tm->stage == ST_MODE) && now - tm->stage_tx >= TUYAMCU_RETRY_MS) {
        tm->stage_tx = now;
        tm_tx(tm, tm->stage == ST_PRODUCT ? TM_CMD_PRODUCT : TM_CMD_MODE, NULL, 0);
    }
}

bool tuyamcu_link_up(const tuyamcu *tm)
{
    return tm->link_up;
}

const tuyamcu_stats *tuyamcu_get_stats(tuyamcu *tm)
{
    tm->stats.bad_checksum = tm->parser.bad_sum;
    tm->stats.oversized = tm->parser.overflow;
    return &tm->stats;
}

void tuyamcu_set_net_status(tuyamcu *tm, uint8_t status)
{
    if (status == tm->net_status) return;
    tm->net_status = status;
    if (tm->stage == ST_READY && !tm->mcu_handles_net) tm_push_net_status(tm);
}

tm_err tuyamcu_query_all(tuyamcu *tm)
{
    if (!tm->link_up) return TM_ERR_NOLINK;
    return tm_tx(tm, TM_CMD_QUERY, NULL, 0);
}

tm_err tuyamcu_write_dp(tuyamcu *tm, uint8_t id, uint8_t type, const uint8_t *val, size_t len)
{
    if (!tm_dp_write_allowed(id)) {
        TM_LOG(tm, "tuyamcu write to DP %u refused (not allowlisted)", id);
        return TM_ERR_DENIED;
    }
    if (!tm->link_up) return TM_ERR_NOLINK;
    uint8_t rec[TUYAMCU_TX_MAX - TM_FRAME_OVERHEAD];
    size_t n = tm_dp_put(rec, sizeof rec, id, type, val, len);
    if (!n) return TM_ERR_ARG;
    return tm_tx(tm, TM_CMD_DP_SEND, rec, n);
}

tm_err tuyamcu_write_bool(tuyamcu *tm, uint8_t id, bool v)
{
    uint8_t b = v ? 1 : 0;
    return tuyamcu_write_dp(tm, id, TM_DP_BOOL, &b, 1);
}

tm_err tuyamcu_write_value(tuyamcu *tm, uint8_t id, int32_t v)
{
    uint8_t b[4] = {(uint8_t)((uint32_t)v >> 24), (uint8_t)((uint32_t)v >> 16),
                    (uint8_t)((uint32_t)v >> 8), (uint8_t)v};
    return tuyamcu_write_dp(tm, id, TM_DP_VALUE, b, 4);
}

tm_err tuyamcu_write_enum(tuyamcu *tm, uint8_t id, uint8_t v)
{
    return tuyamcu_write_dp(tm, id, TM_DP_ENUM, &v, 1);
}
