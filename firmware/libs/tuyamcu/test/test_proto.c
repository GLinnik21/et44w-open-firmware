#include "fake.h"
#include "harness.h"
#include "tests.h"

static void test_heartbeat_and_init(void)
{
    fake f;
    fake_init(&f);
    CHECK(!tuyamcu_link_up(&f.tm));

    tuyamcu_poll(&f.tm); /* first poll sends the heartbeat query immediately */
    CHECK_EQ(f.ntx, 1);
    CHECK_EQ(f.tx_cmd[0], TM_CMD_HEARTBEAT);
    CHECK_EQ(f.tx_len[0], 0);
    CHECK_EQ(f.tx_ver[0], 0);
    tuyamcu_poll(&f.tm);
    CHECK_EQ(f.ntx, 1); /* not again before the period */
    f.now += 1000;
    tuyamcu_poll(&f.tm); /* link down: retry every 1 s (baud hunting) */
    CHECK_EQ(f.ntx, 2);

    fake_clear(&f);
    uint8_t zero = 0, one = 1;
    fake_inject(&f, 3, TM_CMD_HEARTBEAT, &zero, 1);
    CHECK(tuyamcu_link_up(&f.tm));
    CHECK_EQ(f.nev, 1);
    CHECK_EQ(f.ev_type[0], TM_EV_LINK_UP);
    CHECK_EQ(f.ntx, 1);
    CHECK_EQ(f.tx_cmd[1 - 1], TM_CMD_PRODUCT);

    fake_inject(&f, 3, TM_CMD_PRODUCT, (const uint8_t *)"{\"p\":\"x\"}", 9);
    CHECK_EQ(f.ev_type[1], TM_EV_PRODUCT);
    CHECK_EQ(f.tx_cmd[1], TM_CMD_MODE);

    fake_inject(&f, 3, TM_CMD_MODE, NULL, 0); /* module handles Wi-Fi LED */
    CHECK_EQ(f.tx_cmd[2], TM_CMD_NET_REPORT);
    CHECK_EQ(f.tx_data[2][0], TM_NET_NO_LINK);
    CHECK_EQ(f.tx_cmd[3], TM_CMD_QUERY);
    CHECK_EQ(f.ntx, 4);

    /* later heartbeat replies (1) do not restart anything */
    fake_clear(&f);
    f.now += 15000;
    tuyamcu_poll(&f.tm);
    CHECK_EQ(f.ntx, 1);
    fake_inject(&f, 3, TM_CMD_HEARTBEAT, &one, 1);
    CHECK_EQ(f.ntx, 1);
    CHECK_EQ(f.nev, 0);
    /* a reply of 0 means the MCU rebooted: init runs again */
    fake_inject(&f, 3, TM_CMD_HEARTBEAT, &zero, 1);
    CHECK_EQ(f.tx_cmd[1], TM_CMD_PRODUCT);
}

static void test_mcu_initiated_heartbeat(void)
{
    fake f;
    fake_init(&f);
    fake_inject(&f, 3, TM_CMD_HEARTBEAT, NULL, 0);
    CHECK_EQ(f.tx_cmd[0], TM_CMD_HEARTBEAT);
    CHECK_EQ(f.tx_len[0], 1);
    CHECK_EQ(f.tx_data[0][0], 0); /* first answer 0 */
    fake_inject(&f, 3, TM_CMD_HEARTBEAT, NULL, 0);
    CHECK_EQ(f.tx_data[1][0], 1); /* then 1 */
    CHECK(!tuyamcu_link_up(&f.tm)); /* link needs a reply to OUR heartbeat */
}

static void test_retry_and_link_timeout(void)
{
    fake f;
    fake_init(&f);
    uint8_t zero = 0;
    tuyamcu_poll(&f.tm);
    fake_inject(&f, 3, TM_CMD_HEARTBEAT, &zero, 1);
    fake_clear(&f);
    f.now += 1000; /* link is up so heartbeat is slow; product query not answered */
    tuyamcu_poll(&f.tm);
    CHECK_EQ(f.ntx, 0);
    f.now += 1000;
    tuyamcu_poll(&f.tm);
    CHECK_EQ(fake_count_cmd(&f, TM_CMD_PRODUCT), 1);

    f.now += TUYAMCU_LINK_TIMEOUT_MS;
    fake_clear(&f);
    tuyamcu_poll(&f.tm);
    CHECK(!tuyamcu_link_up(&f.tm));
    CHECK_EQ(f.ev_type[0], TM_EV_LINK_DOWN);
}

static void test_dp_report_events(void)
{
    fake f;
    fake_init(&f);
    fake_link_up(&f);
    const uint8_t rep[] = {3, TM_DP_ENUM, 0, 1, 1,            /* work_state */
                           24, TM_DP_VALUE, 0, 4, 0, 0, 0, 0xEB, /* 23.5 C */
                           1, TM_DP_BOOL, 0, 1, 1};
    fake_inject(&f, 3, TM_CMD_DP_REPORT, rep, sizeof rep);
    CHECK_EQ(f.nev, 3);
    CHECK_EQ(f.ev_type[0], TM_EV_DP);
    CHECK_EQ(f.ev_dpid[1], 24);
    CHECK_EQ(f.ev_u32[1], 235);
    CHECK_EQ(f.ev_dpid[2], 1);
    CHECK_EQ(f.ntx, 0); /* reports are not acked */
}

static void test_write_allowlist(void)
{
    fake f;
    fake_init(&f);
    CHECK_EQ(tuyamcu_write_bool(&f.tm, 1, true), TM_ERR_NOLINK);
    CHECK_EQ(tuyamcu_write_bool(&f.tm, 115, true), TM_ERR_DENIED); /* denied even before link */
    fake_link_up(&f);

    CHECK_EQ(tuyamcu_write_bool(&f.tm, 115, true), TM_ERR_DENIED); /* factory reset */
    CHECK_EQ(tuyamcu_write_enum(&f.tm, 115, 1), TM_ERR_DENIED);
    CHECK_EQ(tuyamcu_write_dp(&f.tm, 115, TM_DP_RAW, (const uint8_t *)"", 0), TM_ERR_DENIED);
    CHECK_EQ(tuyamcu_write_value(&f.tm, 121, 900), TM_ERR_DENIED); /* floor limit */
    CHECK_EQ(tuyamcu_write_value(&f.tm, 116, 5), TM_ERR_DENIED);   /* heater power */
    CHECK_EQ(tuyamcu_write_value(&f.tm, 119, 5), TM_ERR_DENIED);
    CHECK_EQ(f.ntx, 0); /* nothing hit the wire */

    CHECK_EQ(tuyamcu_write_bool(&f.tm, 1, true), TM_OK);
    CHECK_EQ(tuyamcu_write_enum(&f.tm, 2, 0), TM_OK);
    CHECK_EQ(tuyamcu_write_value(&f.tm, 16, 215), TM_OK);
    CHECK_EQ(tuyamcu_write_bool(&f.tm, 108, false), TM_OK);
    CHECK_EQ(tuyamcu_write_enum(&f.tm, 107, 0), TM_ERR_DENIED); /* display unit is read-only */
    CHECK_EQ(f.ntx, 4);
    CHECK_EQ(f.tx_cmd[2], TM_CMD_DP_SEND);
    const uint8_t exp[] = {16, TM_DP_VALUE, 0, 4, 0, 0, 0, 215};
    CHECK_EQ(f.tx_len[2], sizeof exp);
    CHECK_MEM(f.tx_data[2], exp, sizeof exp);

    CHECK_EQ(tuyamcu_write_dp(&f.tm, 16, TM_DP_VALUE, (const uint8_t *)"ab", 2), TM_ERR_ARG);
    CHECK_EQ(f.ntx, 4);
}

static void test_time_reply(void)
{
    fake f;
    fake_init(&f);
    fake_link_up(&f);

    fake_inject(&f, 3, TM_CMD_TIME_LOCAL, NULL, 0); /* not known yet */
    CHECK_EQ(f.tx_cmd[0], TM_CMD_TIME_LOCAL);
    CHECK_EQ(f.tx_len[0], 8);
    CHECK_EQ(f.tx_data[0][0], 0);

    f.time_known = true;
    f.time = (tm_time){2026, 10, 17, 14, 5, 9, 6};
    fake_inject(&f, 3, TM_CMD_TIME_LOCAL, NULL, 0);
    const uint8_t loc[] = {1, 26, 10, 17, 14, 5, 9, 6};
    CHECK_EQ(f.tx_len[1], 8);
    CHECK_MEM(f.tx_data[1], loc, 8);

    fake_inject(&f, 3, TM_CMD_TIME_GMT, NULL, 0);
    CHECK_EQ(f.tx_cmd[2], TM_CMD_TIME_GMT);
    CHECK_EQ(f.tx_len[2], 7);
    CHECK_MEM(f.tx_data[2], loc, 7);
}

static void test_wifi_reset(void)
{
    fake f;
    fake_init(&f);
    fake_link_up(&f);
    fake_inject(&f, 3, TM_CMD_WIFI_RESET, NULL, 0);
    CHECK_EQ(f.tx_cmd[0], TM_CMD_WIFI_RESET); /* ack */
    CHECK_EQ(f.tx_len[0], 0);
    CHECK_EQ(f.ev_type[0], TM_EV_WIFI_RESET);
    CHECK_EQ(f.ev_arg[0], TM_RESET_PLAIN);
    const uint8_t ap = 1;
    fake_inject(&f, 3, TM_CMD_WIFI_MODE, &ap, 1);
    CHECK_EQ(f.tx_cmd[1], TM_CMD_WIFI_MODE);
    CHECK_EQ(f.ev_arg[1], 1);
}

static void test_net_status(void)
{
    fake f;
    fake_init(&f);
    fake_link_up(&f);
    tuyamcu_set_net_status(&f.tm, TM_NET_PAIRED);
    CHECK_EQ(f.ntx, 1);
    CHECK_EQ(f.tx_cmd[0], TM_CMD_NET_REPORT);
    CHECK_EQ(f.tx_data[0][0], 4);
    tuyamcu_set_net_status(&f.tm, TM_NET_PAIRED); /* unchanged: nothing sent */
    CHECK_EQ(f.ntx, 1);
    fake_inject(&f, 3, TM_CMD_NET_REPORT, NULL, 0); /* MCU's ack: no reply */
    CHECK_EQ(f.ntx, 1);
    fake_inject(&f, 3, TM_CMD_NET_QUERY, NULL, 0); /* MCU asks: answered with 0x2B */
    CHECK_EQ(f.ntx, 2);
    CHECK_EQ(f.tx_cmd[1], TM_CMD_NET_QUERY);
    CHECK_EQ(f.tx_data[1][0], 4);

    /* protocol ver < 3: "paired" collapses to 0x03 */
    fake_init(&f);
    uint8_t zero = 0;
    tuyamcu_poll(&f.tm);
    fake_inject(&f, 0, TM_CMD_HEARTBEAT, &zero, 1);
    fake_inject(&f, 0, TM_CMD_PRODUCT, (const uint8_t *)"{}", 2);
    fake_clear(&f);
    tuyamcu_set_net_status(&f.tm, TM_NET_PAIRED);
    fake_inject(&f, 0, TM_CMD_MODE, NULL, 0);
    CHECK_EQ(f.tx_cmd[0], TM_CMD_NET_REPORT);
    CHECK_EQ(f.tx_data[0][0], TM_NET_UNPAIRED);

    /* MCU that handles its own Wi-Fi LED (mode reply has 2 bytes): no status pushed */
    fake_init(&f);
    tuyamcu_poll(&f.tm);
    fake_inject(&f, 3, TM_CMD_HEARTBEAT, &zero, 1);
    fake_inject(&f, 3, TM_CMD_PRODUCT, (const uint8_t *)"{}", 2);
    fake_clear(&f);
    const uint8_t pins[] = {2, 3};
    fake_inject(&f, 3, TM_CMD_MODE, pins, 2);
    CHECK_EQ(fake_count_cmd(&f, TM_CMD_NET_REPORT), 0);
    CHECK_EQ(fake_count_cmd(&f, TM_CMD_QUERY), 1);
}

static void test_ignored_commands(void)
{
    fake f;
    fake_init(&f);
    fake_link_up(&f);
    const uint8_t cmds[] = {0xF0, 0x0A, 0x0B, 0x0E, 0x22, 0x34, 0x77};
    for (unsigned i = 0; i < sizeof cmds; i++) fake_inject(&f, 3, cmds[i], (const uint8_t *)"xyz", 3);
    CHECK_EQ(f.ntx, 0);
    CHECK_EQ(f.nev, 0);
    /* still healthy afterwards */
    fake_inject(&f, 3, TM_CMD_TIME_GMT, NULL, 0);
    CHECK_EQ(f.ntx, 1);
}

static void test_rx_garbage_and_stats(void)
{
    fake f;
    fake_init(&f);
    uint8_t zero = 0, buf[40];
    tuyamcu_poll(&f.tm);
    fake_clear(&f);
    const uint8_t junk[] = {0xFF, 0x55, 0x00, 0x13, 0x55, 0xAA, 0xFF};
    tuyamcu_rx(&f.tm, junk, sizeof junk);
    size_t n = tm_frame_build(buf, sizeof buf, 3, TM_CMD_HEARTBEAT, &zero, 1);
    tuyamcu_rx(&f.tm, buf, n / 2); /* split delivery */
    CHECK(!tuyamcu_link_up(&f.tm));
    tuyamcu_rx(&f.tm, buf + n / 2, n - n / 2);
    CHECK(tuyamcu_link_up(&f.tm));
    CHECK(tuyamcu_get_stats(&f.tm)->frames_ok >= 1);

    tuyamcu_link_reset(&f.tm); /* e.g. baud change */
    CHECK(!tuyamcu_link_up(&f.tm));
    fake_clear(&f);
    tuyamcu_poll(&f.tm);
    CHECK_EQ(fake_count_cmd(&f, TM_CMD_HEARTBEAT), 1);
}

static void test_frame_hook(void)
{
    fake f;
    fake_init(&f);
    fake_link_up(&f);
    fake_inject(&f, 3, TM_CMD_TIME_LOCAL, NULL, 0); /* rx, then our reply */
    const uint8_t junk[] = {0x55, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x00}; /* bad checksum: not reported */
    tuyamcu_rx(&f.tm, junk, sizeof junk);
    CHECK_EQ(f.nframe, 2);
    CHECK(!f.frame_tx[0]);
    CHECK_EQ(f.frame_cmd[0], TM_CMD_TIME_LOCAL);
    CHECK(f.frame_tx[1]);
    CHECK_EQ(f.frame_cmd[1], TM_CMD_TIME_LOCAL);
    CHECK_EQ(f.frame_len[1], 8);
}

void run_proto_tests(void)
{
    RUN(test_heartbeat_and_init);
    RUN(test_mcu_initiated_heartbeat);
    RUN(test_retry_and_link_timeout);
    RUN(test_dp_report_events);
    RUN(test_write_allowlist);
    RUN(test_time_reply);
    RUN(test_wifi_reset);
    RUN(test_net_status);
    RUN(test_ignored_commands);
    RUN(test_rx_garbage_and_stats);
    RUN(test_frame_hook);
}
