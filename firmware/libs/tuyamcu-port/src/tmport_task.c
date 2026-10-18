#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include "FreeRTOS.h"
#include "queue.h"
#include "task.h"

#include "tmport_uart.h"
#include "tuyamcu_port.h"

#define BAUD_A          9600u
#define BAUD_B          115200u
#define PROBE_MS        5000u
#define STATS_MS        600000u
#define RX_WAIT_MS      50u
#define CMD_QUEUE_LEN   16
#define STACK_WORDS     512 // measured use ~215 words
#define TASK_PRIO       (tskIDLE_PRIORITY + 2)
#define HEX_MAX         32 /* payload bytes shown per frame */

/* Commands for the port task. */
typedef enum { CMD_NET_STATUS, CMD_WRITE, CMD_QUERY_ALL } cmd_type;
typedef struct {
    uint8_t type; /* cmd_type */
    uint8_t arg;  /* net status, or DP id */
    uint8_t dp_type;
    int32_t value;
} port_cmd;

static tuyamcu s_tm;
static QueueHandle_t s_cmds;
static tuyamcu_port_config s_cfg;

/* Heartbeats (15 s) and the MCU's time requests (5 s) would flush the 8 KiB netlog ring within
 * minutes; they are only counted in the stats line. */
static bool IsRoutine(uint8_t cmd) {
    return cmd == TM_CMD_HEARTBEAT || cmd == TM_CMD_TIME_LOCAL || cmd == TM_CMD_TIME_GMT;
}

/* One line per frame: "tmcu rx 07 [5] 10 02 00 01 01". The netlog on port 2323 has no authentication,
 * which is acceptable for what crosses this link: DP values (setpoint, mode, temperatures, settings,
 * the weekly schedule DP 119 — all also on the unauthenticated web page), the MCU's product info
 * (public product key and version) and status commands. Wi-Fi credentials and keys never go to the
 * MCU, and the module sends nothing else. */
static void IoFrame(void *ctx, bool tx, const tm_frame *f) {
    (void) ctx;
    if (IsRoutine(f->cmd)) {
        return;
    }
    size_t shown = f->len < HEX_MAX ? f->len : HEX_MAX;
    char hex[HEX_MAX * 3 + 1] = "";
    for (size_t i = 0; i < shown; i++) {
        snprintf(&hex[i * 3], 4, " %02x", f->data[i]);
    }
    printf("tmcu %s %02x [%u]%s%s\n", tx ? "tx" : "rx", f->cmd, (unsigned) f->len, hex,
           shown < f->len ? " ..." : "");
}

static int IoWrite(void *ctx, const uint8_t *buf, size_t n) {
    (void) ctx;
    tmport_uart_write(buf, n);
    return (int) n;
}

static uint32_t IoNowMs(void *ctx) {
    (void) ctx;
    return (uint32_t) ((uint64_t) xTaskGetTickCount() * 1000u / configTICK_RATE_HZ);
}

static bool IoGetTime(void *ctx, bool local, tm_time *t) {
    (void) ctx;
    return s_cfg.get_time != NULL && s_cfg.get_time(local, t, s_cfg.ctx);
}

static void IoLog(void *ctx, const char *fmt, ...) {
    (void) ctx;
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static void IoEvent(void *ctx, const tm_event *ev) {
    (void) ctx;
    if (s_cfg.on_event != NULL) {
        s_cfg.on_event(ev, s_cfg.ctx);
    }
}

static tm_err Write(const port_cmd *c) {
    switch (c->dp_type) {
        case TM_DP_BOOL: return tuyamcu_write_bool(&s_tm, c->arg, c->value != 0);
        case TM_DP_VALUE: return tuyamcu_write_value(&s_tm, c->arg, c->value);
        case TM_DP_ENUM:
            if (c->value < 0 || c->value > UINT8_MAX) {
                return TM_ERR_ARG; /* would be sent as a different, valid value */
            }
            return tuyamcu_write_enum(&s_tm, c->arg, (uint8_t) c->value);
        default: return TM_ERR_ARG;
    }
}

static void HandleCmd(const port_cmd *c) {
    tm_err err = TM_OK;
    switch ((cmd_type) c->type) {
        case CMD_NET_STATUS:
            tuyamcu_set_net_status(&s_tm, c->arg);
            break;
        case CMD_WRITE:
            err = Write(c);
            break;
        case CMD_QUERY_ALL:
            err = tuyamcu_query_all(&s_tm);
            break;
    }
    if (err != TM_OK) {
        printf("tmcu: cmd %u dp %u failed (%d)\n", (unsigned) c->type, (unsigned) c->arg, (int) err);
    }
}

static void SwitchBaud(uint32_t baud) {
    printf("tmcu baud -> %u\n", (unsigned) baud);
    vTaskDelay(pdMS_TO_TICKS(5)); /* TX is busy-wait, so only the last byte can still be shifting */
    tmport_uart_set_baud(baud);
    tmport_uart_flush_rx();
    tuyamcu_link_reset(&s_tm);
}

/* Alternates BAUD_A/BAUD_B every PROBE_MS until the link is up, then stays. */
static void ProbeBaud(uint32_t now, uint32_t *baud, uint32_t *since, bool *locked) {
    if (*locked) {
        return;
    }
    if (tuyamcu_link_up(&s_tm)) {
        *locked = true;
        printf("tmcu baud locked at %u\n", (unsigned) *baud);
    } else if (now - *since >= PROBE_MS) {
        *baud = (*baud == BAUD_A) ? BAUD_B : BAUD_A;
        SwitchBaud(*baud);
        *since = now;
    }
}

static void LogStats(void) {
    const tuyamcu_stats *s = tuyamcu_get_stats(&s_tm);
    printf("tmcu stats ok=%u badsum=%u oversized=%u rxdrop=%u tx=%u link=%d\n", (unsigned) s->frames_ok,
           (unsigned) s->bad_checksum, (unsigned) s->oversized, (unsigned) tmport_uart_dropped(),
           (unsigned) s->tx_frames, (int) tuyamcu_link_up(&s_tm));
}

static void PortTask(void *arg) {
    (void) arg;
    uint32_t baud = BAUD_A;
    bool locked = false;
    uint32_t since = IoNowMs(NULL);
    uint32_t stats_at = since;
    uint8_t buf[64];

    for (;;) {
        size_t n = tmport_uart_read(buf, sizeof buf, pdMS_TO_TICKS(RX_WAIT_MS));
        if (n > 0) {
            tuyamcu_rx(&s_tm, buf, n);
        }
        port_cmd c;
        while (xQueueReceive(s_cmds, &c, 0) == pdTRUE) {
            HandleCmd(&c);
        }
        tuyamcu_poll(&s_tm);
        uint32_t now = IoNowMs(NULL);
        ProbeBaud(now, &baud, &since, &locked);
        if (now - stats_at >= STATS_MS) {
            stats_at = now;
            LogStats();
        }
    }
}

bool tuyamcu_port_start(const tuyamcu_port_config *config) {
    s_cfg = *config;
    tuyamcu_io io = {
        .ctx = NULL,
        .write = IoWrite,
        .now_ms = IoNowMs,
        .get_time = IoGetTime,
        .log = IoLog,
        .on_event = IoEvent,
        .on_frame = IoFrame,
    };
    tuyamcu_init(&s_tm, &io);
    s_cmds = xQueueCreate(CMD_QUEUE_LEN, sizeof(port_cmd));
    if (s_cmds == NULL || tmport_uart_open(BAUD_A) != 0 ||
        xTaskCreate(PortTask, "tmport", STACK_WORDS, NULL, TASK_PRIO, NULL) != pdPASS) {
        printf("tmcu: init failed\n");
        if (s_cmds != NULL) {
            vQueueDelete(s_cmds);
            s_cmds = NULL; /* the calls below then return false */
        }
        return false;
    }
    return true;
}

static bool Post(const port_cmd *c) {
    return s_cmds != NULL && xQueueSend(s_cmds, c, 0) == pdTRUE;
}

bool tuyamcu_port_set_net_status(uint8_t status) {
    return Post(&(port_cmd) {.type = CMD_NET_STATUS, .arg = status});
}

bool tuyamcu_port_write(uint8_t dp, uint8_t type, int32_t value) {
    return Post(&(port_cmd) {.type = CMD_WRITE, .arg = dp, .dp_type = type, .value = value});
}

bool tuyamcu_port_query_all(void) {
    return Post(&(port_cmd) {.type = CMD_QUERY_ALL});
}
