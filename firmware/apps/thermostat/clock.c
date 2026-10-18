#include "clock.h"

#include <stdio.h>

#include "FreeRTOS.h"
#include "lwip/tcpip.h" // first: defines err_t for dns.h
#include "lwip/dns.h"
#include "sntp/sntp.h"
#include "task.h"

#include "config.h"
#include "tz.h"

static tz_zone zone;
static volatile bool started;

static void StartOnTcpip(void* arg) {
    (void) arg;
    ip_addr_t fallback;
    if (ipaddr_aton(THERMOSTAT_DNS_FALLBACK, &fallback)) {
        dns_setserver(1, &fallback);
    }
    sntp_init();
}

void clock_start(void) {
    if (started) {
        return;
    }
    started = true;
    if (!tz_parse(THERMOSTAT_TZ, &zone)) {
        printf("clock: bad TZ \"%s\", using UTC\n", THERMOSTAT_TZ);
    }
    // lwIP raw API (udp_new, dns, sys_timeout) belongs on the TCP/IP thread.
    if (tcpip_callback(StartOnTcpip, NULL) != ERR_OK) {
        printf("clock: sntp start failed\n");
        started = false;
    }
}

#define UNSYNCED_LOG_MS 60000u

/** Once a minute while unsynced, with the DNS servers SNTP depends on. */
static void LogUnsynced(void) {
    static TickType_t last;
    TickType_t now = xTaskGetTickCount();
    if (last && now - last < pdMS_TO_TICKS(UNSYNCED_LOG_MS)) {
        return;
    }
    last = now;
    char dns0[IPADDR_STRLEN_MAX];
    ipaddr_ntoa_r(dns_getserver(0), dns0, sizeof dns0);
    printf("clock: no SNTP time yet (started %d, dns %s, %s)\n", (int) started, dns0, ipaddr_ntoa(dns_getserver(1)));
}

/** Seconds since 1970 (UTC), or 0 before the first SNTP reply. */
static int64_t Now(void) {
    long sec, usec, sec2, usec2;
    unsigned int tick, tick2;
    do { // SNTP updates the three values from the TCP/IP task: read until stable
        sntp_get_lasttime(&sec, &usec, &tick);
        sntp_get_lasttime(&sec2, &usec2, &tick2);
    } while (sec != sec2 || tick != tick2);
    if (sec <= 0) {
        return 0;
    }
    TickType_t elapsed = xTaskGetTickCount() - (TickType_t) tick;
    return (int64_t) sec + (int64_t) (elapsed / configTICK_RATE_HZ);
}

int64_t clock_unix(void) { return Now(); }

bool clock_get(bool local, tm_time* t) {
    int64_t now = Now();
    if (now == 0) {
        LogUnsynced();
        return false;
    }
    tz_civil c;
    if (local) {
        tz_local(&zone, now, &c);
    } else {
        tz_civil_from_epoch(now, &c);
    }
    *t = (tm_time) { .year = c.year, .month = c.month, .day = c.day, .hour = c.hour,
                     .minute = c.minute, .second = c.second, .weekday = c.weekday };
    return true;
}
