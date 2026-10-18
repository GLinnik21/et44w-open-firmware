/* TuyaMCU protocol core, Wi-Fi module side. Pure C: no OS, no malloc, no globals. The platform feeds
 * received bytes with tuyamcu_rx(), calls tuyamcu_poll() periodically (>= every 100 ms) and supplies
 * I/O through tuyamcu_io. One instance is not thread-safe; drive it from one task.
 *
 * Flow (module initiates, MCU answers): heartbeat 0x00 until the MCU replies (link up) -> product
 * info 0x01 -> working mode 0x02 -> network status + query-all 0x08 -> MCU DP reports 0x07. A
 * heartbeat reply of 0 later means the MCU restarted and the sequence runs again.
 */
#ifndef TUYAMCU_H
#define TUYAMCU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tm_cmd.h"
#include "tm_dp.h"
#include "tm_frame.h"
#include "tm_time.h"

#ifndef TUYAMCU_MAX_PAYLOAD
#define TUYAMCU_MAX_PAYLOAD 512u /* largest accepted MCU->module payload, must be >= 256 */
#endif
#define TUYAMCU_TX_MAX 96u /* largest frame we send */

typedef enum {
    TM_OK = 0,
    TM_ERR_DENIED = -1, /* DP not in the write allowlist */
    TM_ERR_ARG = -2,    /* illegal type/length, or does not fit */
    TM_ERR_NOLINK = -3, /* MCU link not up */
    TM_ERR_IO = -4      /* write callback failed */
} tm_err;

typedef enum {
    TM_EV_LINK_UP,    /* first heartbeat reply */
    TM_EV_LINK_DOWN,  /* nothing valid heard for TUYAMCU_LINK_TIMEOUT_MS */
    TM_EV_PRODUCT,    /* data/len = product info JSON (not NUL-terminated) */
    TM_EV_WIFI_RESET, /* MCU asked for a Wi-Fi reset (already acked); arg = mode or TM_RESET_PLAIN */
    TM_EV_DP          /* dp = one reported record (valid only during the callback) */
} tm_event_type;

#define TM_RESET_PLAIN 0xFFu /* cmd 0x04 carries no mode; cmd 0x05 carries 0 SmartConfig / 1 AP */

typedef struct {
    tm_event_type type;
    const tm_dp *dp;
    const uint8_t *data;
    size_t len;
    uint8_t arg;
} tm_event;

typedef struct {
    void *ctx;
    int (*write)(void *ctx, const uint8_t *buf, size_t n); /* one whole frame; < 0 on error */
    uint32_t (*now_ms)(void *ctx);                         /* monotonic, may wrap */
    /* Fill *t and return true; false = time not known yet (replied as "not available"). */
    bool (*get_time)(void *ctx, bool local, tm_time *t);
    void (*log)(void *ctx, const char *fmt, ...); /* optional; one line per call, no trailing \n */
    void (*on_event)(void *ctx, const tm_event *ev);
    /* Optional: every valid frame in both directions (tx = sent by us), e.g. for a frame log. */
    void (*on_frame)(void *ctx, bool tx, const tm_frame *f);
} tuyamcu_io;

typedef struct {
    uint32_t frames_ok;
    uint32_t bad_checksum;
    uint32_t oversized;
    uint32_t tx_frames;
} tuyamcu_stats;

/* Timing (ms). */
#define TUYAMCU_HB_DOWN_MS 1000u      /* heartbeat period while the link is down */
#define TUYAMCU_HB_UP_MS 15000u       /* ... and while up */
#define TUYAMCU_LINK_TIMEOUT_MS 45000u
#define TUYAMCU_RETRY_MS 2000u        /* resend product/mode query */

typedef struct {
    tuyamcu_io io;
    tm_parser parser;
    uint8_t rx[TUYAMCU_MAX_PAYLOAD + TM_FRAME_OVERHEAD];
    uint8_t tx[TUYAMCU_TX_MAX];
    uint8_t stage;
    uint8_t net_status;
    uint8_t mcu_ver;
    bool link_up;
    bool hb_sent;
    bool hb_answered_once; /* for replying to MCU-initiated heartbeats */
    bool mcu_handles_net;  /* working mode reply said the MCU drives its own Wi-Fi LED */
    uint32_t last_hb, last_rx, stage_tx;
    tuyamcu_stats stats;
} tuyamcu;

void tuyamcu_init(tuyamcu *tm, const tuyamcu_io *io);

/* Forget link state and parser (call after changing the UART baud rate). Keeps net status. */
void tuyamcu_link_reset(tuyamcu *tm);

void tuyamcu_rx(tuyamcu *tm, const uint8_t *buf, size_t n);
void tuyamcu_poll(tuyamcu *tm);

bool tuyamcu_link_up(const tuyamcu *tm);
const tuyamcu_stats *tuyamcu_get_stats(tuyamcu *tm); /* refreshes parser counters */

/* Sets the TM_NET_* status. Pushed to the MCU (0x03) when it changes and once the link is ready,
 * unless the MCU's working-mode reply said it drives its own Wi-Fi LED; it is still answered when
 * the MCU asks for it (0x2B). */
void tuyamcu_set_net_status(tuyamcu *tm, uint8_t status);

/* Asks the MCU to report all DPs (0x08). */
tm_err tuyamcu_query_all(tuyamcu *tm);

/* DP writes (cmd 0x06). Only allowlisted DPs (tm_allow.h) are sent; others return TM_ERR_DENIED. */
tm_err tuyamcu_write_dp(tuyamcu *tm, uint8_t id, uint8_t type, const uint8_t *val, size_t len);
tm_err tuyamcu_write_bool(tuyamcu *tm, uint8_t id, bool v);
tm_err tuyamcu_write_value(tuyamcu *tm, uint8_t id, int32_t v);
tm_err tuyamcu_write_enum(tuyamcu *tm, uint8_t id, uint8_t v);

#endif
