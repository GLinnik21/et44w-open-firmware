#include "web.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "dp_cache.h"
#include "httpd.h"
#include "http_parse.h"
#include "thermo_mcu.h"
#include "thermo_dp.h"
#include "web_page.h" // generated from web/index.html: kWebPage, kWebPageLen

static struct {
    const char* name;
    const char* fw;
} web;

#define SEND_CHUNK 1024 // lwIP copies sends into its own heap, which HAP/Matter share

static dp_cache_snapshot snapshot; // one client at a time (httpd)

static void SendPage(int sock) {
    httpd_begin(sock, 200, "text/html; charset=utf-8");
    for (size_t off = 0; off < kWebPageLen; off += SEND_CHUNK) {
        size_t n = kWebPageLen - off < SEND_CHUNK ? kWebPageLen - off : SEND_CHUNK;
        httpd_send(sock, kWebPage + off, n);
    }
}

static int32_t NumberOf(const dp_cache_entry* e) {
    uint32_t v = 0;
    for (unsigned i = 0; i < e->len && i < 4; i++) {
        v = v << 8 | e->value[i];
    }
    return (int32_t) v;
}

static void SendHex(int sock, const dp_cache_entry* e) {
    char hex[DP_CACHE_VAL_MAX * 2 + 1];
    for (unsigned i = 0; i < e->len; i++) {
        snprintf(&hex[i * 2], 3, "%02x", e->value[i]);
    }
    hex[e->len * 2] = '\0';
    httpd_printf(sock, "\"%s\"", hex);
}

static void SendValue(int sock, const dp_cache_entry* e) {
    if (e->type == TM_DP_RAW || e->type == TM_DP_STRING) {
        SendHex(sock, e);
    } else {
        httpd_printf(sock, "%ld", (long) NumberOf(e));
    }
}

// {"name":..,"fw":..,"uptime":s,"heap":..,"heapMin":..,"dp":{"setpoint":215,..},"other":{"125":..},
//  "schedule":["01000700..",null,..]}
static void SendState(int sock) {
    dp_cache_get(&snapshot);
    httpd_begin(sock, 200, "application/json");
    httpd_printf(sock, "{\"name\":\"%s\",\"fw\":\"%s\",\"uptime\":%lu,\"heap\":%u,\"heapMin\":%u,\"dp\":{",
                 web.name, web.fw,
                 (unsigned long) (xTaskGetTickCount() / configTICK_RATE_HZ), (unsigned) xPortGetFreeHeapSize(),
                 (unsigned) xPortGetMinimumEverFreeHeapSize());
    const char* sep = "";
    for (unsigned i = 0; i < snapshot.count; i++) { // DPs in the table, by name
        const thermo_dp_info* d = thermo_dp_find(snapshot.dps[i].id);
        if (d) {
            httpd_printf(sock, "%s\"%s\":", sep, d->name);
            SendValue(sock, &snapshot.dps[i]);
            sep = ",";
        }
    }
    httpd_printf(sock, "},\"other\":{");
    sep = "";
    for (unsigned i = 0; i < snapshot.count; i++) { // anything else the MCU reports, by id
        if (!thermo_dp_find(snapshot.dps[i].id)) {
            httpd_printf(sock, "%s\"%u\":", sep, snapshot.dps[i].id);
            SendValue(sock, &snapshot.dps[i]);
            sep = ",";
        }
    }
    httpd_printf(sock, "},\"schedule\":[");
    for (unsigned i = 0; i < DP_CACHE_DAYS; i++) {
        if (i) {
            httpd_send(sock, ",", 1);
        }
        if (snapshot.days[i].len) {
            SendHex(sock, &snapshot.days[i]);
        } else {
            httpd_send(sock, "null", 4);
        }
    }
    httpd_send(sock, "]}", 2);
}

static bool ParseInt(const char* text, int32_t* out) {
    char* end;
    long v = strtol(text, &end, 10);
    if (end == text || *end || v < INT32_MIN || v > INT32_MAX) {
        return false;
    }
    *out = (int32_t) v;
    return true;
}

static void WriteDp(int sock, const httpd_request* rq) {
    char text[16];
    int32_t id, value;
    if (!http_form_get(rq->body, rq->bodyLen, "dp", text, sizeof text) || !ParseInt(text, &id) || id < 0 ||
        id > 255 || !http_form_get(rq->body, rq->bodyLen, "v", text, sizeof text) || !ParseInt(text, &value)) {
        httpd_reply(sock, 400, "expected dp=<id>&v=<integer>");
        return;
    }
    const char* refused = thermo_dp_check_write((uint8_t) id, value);
    if (refused) {
        httpd_reply(sock, 400, refused);
        return;
    }
    printf("web: write dp %ld = %ld\n", (long) id, (long) value);
    if (!thermo_mcu_write((uint8_t) id, (thermo_wtype) thermo_dp_find((uint8_t) id)->type, value)) {
        httpd_reply(sock, 500, "MCU queue full, try again");
        return;
    }
    httpd_reply(sock, 200, "ok");
}

static void Handle(int sock, const httpd_request* rq, void* ctx) {
    (void) ctx;
    bool get = !strcmp(rq->method, "GET");
    if (!strcmp(rq->path, "/")) {
        get ? SendPage(sock) : httpd_reply(sock, 405, "GET only");
    } else if (!strcmp(rq->path, "/api/state")) {
        get ? SendState(sock) : httpd_reply(sock, 405, "GET only");
    } else if (!strcmp(rq->path, "/api/dp")) {
        !strcmp(rq->method, "POST") ? WriteDp(sock, rq) : httpd_reply(sock, 405, "POST only");
    } else {
        httpd_reply(sock, 404, "not found");
    }
}

void web_start(const char* name, const char* fw) {
    web.name = name;
    web.fw = fw;
    httpd_start(WEB_PORT, Handle, NULL);
}
