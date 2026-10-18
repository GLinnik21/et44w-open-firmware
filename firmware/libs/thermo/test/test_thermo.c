#include "harness.h"
#include "thermo.h"
#include "thermo_dp.h"
#include "tm_allow.h"

int t_checks, t_fails;

static const thermo_cfg kCfg = {.mode_hold = 0, .mode_smart = 1, .mode_holiday = 2, .state_heating = 0};
static const thermo_cfg kUnknown = {THERMO_RAW_UNKNOWN, THERMO_RAW_UNKNOWN, THERMO_RAW_UNKNOWN,
                                    THERMO_RAW_UNKNOWN};

static void Boot(thermo *t, const thermo_cfg *cfg)
{
    thermo_init(t, cfg);
    CHECK(!thermo_ready(t));
    thermo_report(t, 1, 1, 0);
    thermo_report(t, 2, 1, 0);
    thermo_report(t, 3, 1, 0);
    thermo_report(t, 16, 300, 0);
    thermo_report(t, 24, 268, 0);
    thermo_report(t, 104, 0, 0);
    CHECK(thermo_ready(t));
}

static void test_view(void)
{
    thermo t;
    Boot(&t, &kCfg);
    CHECK(thermo_dp_used(THERMO_DP_SETPOINT) && thermo_dp_used(THERMO_DP_FAULT));
    CHECK(!thermo_dp_used(108) && !thermo_dp_used(17) && !thermo_dp_used(119) && !thermo_dp_used(0));
    CHECK_EQ(thermo_target_state(&t), THERMO_MODE_AUTO);
    CHECK_EQ(thermo_current_state(&t), THERMO_MODE_OFF); /* DP3 1 != heating 0 */
    CHECK_EQ(thermo_target_tenths(&t), 300);
    CHECK_EQ(thermo_current_tenths(&t), 268);
    CHECK(!thermo_fault(&t));
    CHECK(thermo_report(&t, 3, 0, 10));
    CHECK_EQ(thermo_current_state(&t), THERMO_MODE_HEAT);
    CHECK(thermo_report(&t, 2, 0, 10));
    CHECK_EQ(thermo_target_state(&t), THERMO_MODE_HEAT);
    CHECK(thermo_report(&t, 2, 2, 10)); /* holiday shows as Auto */
    CHECK_EQ(thermo_target_state(&t), THERMO_MODE_AUTO);
    CHECK(thermo_report(&t, 1, 0, 10));
    CHECK_EQ(thermo_target_state(&t), THERMO_MODE_OFF);
    CHECK_EQ(thermo_current_state(&t), THERMO_MODE_OFF);
    CHECK(thermo_report(&t, 104, 2, 10));
    CHECK(thermo_fault(&t));
    CHECK(!thermo_report(&t, 24, 268, 10)); /* no change */
    CHECK(!thermo_report(&t, 117, 5, 10));  /* not ours */
    CHECK(thermo_report(&t, 16, 1000, 10));
    CHECK_EQ(thermo_target_tenths(&t), THERMO_SET_MAX);
}

static void test_setpoint_hold(void)
{
    thermo t;
    thermo_write w[THERMO_MAX_WRITES];
    Boot(&t, &kCfg);
    CHECK(thermo_set_target_c(&t, 22.3f, 100));
    CHECK_EQ(thermo_target_tenths(&t), 225);
    CHECK(thermo_set_target_c(&t, 22.2f, 200)); /* slider still moving */
    CHECK_EQ(thermo_target_tenths(&t), 220);
    CHECK(!thermo_report(&t, 16, 300, 300)); /* stale echo held back */
    CHECK_EQ(thermo_target_tenths(&t), 220);
    CHECK(!thermo_tick(&t, 100000)); /* not handed out yet: no expiry */
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 700), 1);
    CHECK_EQ(w[0].dp, 16);
    CHECK_EQ(w[0].type, THERMO_W_VALUE);
    CHECK_EQ(w[0].value, 220);
    CHECK(!thermo_has_writes(&t));
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 700), 0);
    CHECK(!thermo_report(&t, 16, 220, 900)); /* confirmed */
    CHECK(!t.s[THERMO_S_SETPOINT].pending);
    CHECK(thermo_report(&t, 16, 250, 1000)); /* knob on the unit */
    CHECK_EQ(thermo_target_tenths(&t), 250);
}

static void test_setpoint_timeout(void)
{
    thermo t;
    thermo_write w[THERMO_MAX_WRITES];
    Boot(&t, &kCfg);
    thermo_set_target_c(&t, 25.0f, 0);
    thermo_take_writes(&t, w, THERMO_MAX_WRITES, 500);
    CHECK(!thermo_tick(&t, 500 + THERMO_PENDING_MS - 1));
    CHECK(thermo_tick(&t, 500 + THERMO_PENDING_MS)); /* MCU never confirmed: snap to the report */
    CHECK_EQ(thermo_target_tenths(&t), 300);
}

/* A write back to the reported value while another is in flight must still go out: the MCU may
 * yet apply the earlier one. */
static void test_rewrite_in_flight(void)
{
    thermo t;
    thermo_write w[THERMO_MAX_WRITES];
    Boot(&t, &kCfg);
    thermo_set_target_c(&t, 22.0f, 0);
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 500), 1); /* 220 sent, echo pending */
    thermo_set_target_c(&t, 30.0f, 1000);                             /* back to the report */
    CHECK(thermo_has_writes(&t));
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 1500), 1);
    CHECK_EQ(w[0].value, 300);
    CHECK(!thermo_report(&t, 16, 220, 1600)); /* late echo of the first write held back */
    CHECK_EQ(thermo_target_tenths(&t), 300);
    CHECK(!thermo_report(&t, 16, 300, 1700)); /* the second write lands */
    CHECK(!t.s[THERMO_S_SETPOINT].pending && !t.s[THERMO_S_SETPOINT].sent);

    /* Switch: Off then Heat within one round trip. */
    thermo_report(&t, 2, 0, 2000); /* hold, so Heat doesn't touch the mode */
    thermo_set_target_state(&t, THERMO_MODE_OFF, 2000);
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 2500), 1);
    thermo_set_target_state(&t, THERMO_MODE_HEAT, 2600);
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 3100), 1);
    CHECK_EQ(w[0].dp, 1);
    CHECK_EQ(w[0].value, 1);

    /* Nothing in flight: toggling back still sends nothing. */
    thermo_report(&t, 1, 1, 3200);
    thermo_set_target_c(&t, 25.0f, 4000);
    thermo_set_target_c(&t, 30.0f, 4100);
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 4600), 0);
}

static void test_clamp_round(void)
{
    thermo t;
    thermo_write w[THERMO_MAX_WRITES];
    Boot(&t, &kCfg);
    thermo_set_target_c(&t, 2.0f, 0);
    CHECK_EQ(thermo_target_tenths(&t), 50);
    thermo_set_target_c(&t, 55.0f, 0);
    CHECK_EQ(thermo_target_tenths(&t), 400);
    thermo_set_target_c(&t, 21.74f, 0);
    CHECK_EQ(thermo_target_tenths(&t), 215);
    thermo_set_target_c(&t, 21.76f, 0);
    CHECK_EQ(thermo_target_tenths(&t), 220);
    static const float huge[] = {1e30f, 1.0f / 0.0f, 3e9f, 429496729.6f};
    for (size_t i = 0; i < sizeof huge / sizeof huge[0]; i++) { /* no int32 wrap to an in-range value */
        CHECK(thermo_set_target_c(&t, huge[i], 0));
        CHECK_EQ(t.s[THERMO_S_SETPOINT].want, THERMO_SET_MAX);
        CHECK(thermo_set_target_c(&t, -huge[i], 0));
        CHECK_EQ(t.s[THERMO_S_SETPOINT].want, THERMO_SET_MIN);
    }
    float nan = 0.0f / 0.0f;
    CHECK(!thermo_set_target_c(&t, nan, 0));
    thermo_set_target_c(&t, 30.0f, 0); /* back to the reported value: nothing to send */
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 0), 0);
    CHECK(!t.s[THERMO_S_SETPOINT].pending);
}

static void test_modes(void)
{
    thermo t;
    thermo_write w[THERMO_MAX_WRITES];
    Boot(&t, &kCfg); /* on, smart */
    CHECK(thermo_set_target_state(&t, THERMO_MODE_HEAT, 0));
    CHECK_EQ(thermo_target_state(&t), THERMO_MODE_HEAT);
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 0), 1);
    CHECK_EQ(w[0].dp, 2);
    CHECK_EQ(w[0].type, THERMO_W_ENUM);
    CHECK_EQ(w[0].value, 0);
    thermo_report(&t, 2, 0, 10);

    CHECK(thermo_set_target_state(&t, THERMO_MODE_OFF, 20));
    CHECK_EQ(thermo_target_state(&t), THERMO_MODE_OFF);
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 20), 1);
    CHECK_EQ(w[0].dp, 1);
    CHECK_EQ(w[0].type, THERMO_W_BOOL);
    CHECK_EQ(w[0].value, 0);
    thermo_report(&t, 1, 0, 30);

    CHECK(thermo_set_target_state(&t, THERMO_MODE_AUTO, 40)); /* off+hold -> on+smart, switch first */
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 40), 2);
    CHECK_EQ(w[0].dp, 1);
    CHECK_EQ(w[0].value, 1);
    CHECK_EQ(w[1].dp, 2);
    CHECK_EQ(w[1].value, 1);
    CHECK(!thermo_set_target_state(&t, 2, 50)); /* Cool */
    CHECK(!thermo_has_writes(&t));

    thermo_report(&t, 1, 1, 60);
    thermo_report(&t, 2, 2, 60); /* holiday: Auto stays, no write */
    thermo_tick(&t, 100000);
    CHECK(thermo_set_target_state(&t, THERMO_MODE_AUTO, 100000));
    CHECK(!thermo_has_writes(&t));
}

static void test_unknown_modes(void)
{
    thermo t;
    thermo_write w[THERMO_MAX_WRITES];
    Boot(&t, &kUnknown);
    CHECK(!thermo_auto_supported(&t));
    CHECK_EQ(thermo_target_state(&t), THERMO_MODE_HEAT);
    CHECK(!thermo_set_target_state(&t, THERMO_MODE_AUTO, 0));
    CHECK(thermo_set_target_state(&t, THERMO_MODE_HEAT, 0)); /* already on: nothing */
    CHECK_EQ(thermo_take_writes(&t, w, THERMO_MAX_WRITES, 0), 0);
    CHECK_EQ(thermo_current_state(&t), THERMO_MODE_HEAT); /* guessed: 26.8 < 30.0 */
    thermo_report(&t, 24, 305, 0);
    CHECK_EQ(thermo_current_state(&t), THERMO_MODE_OFF);
}

static void test_wrap(void)
{
    thermo t;
    thermo_write w[THERMO_MAX_WRITES];
    Boot(&t, &kCfg);
    uint32_t now = 0xFFFFFF00u;
    thermo_set_target_c(&t, 22.0f, now);
    thermo_take_writes(&t, w, THERMO_MAX_WRITES, now);
    CHECK(!thermo_tick(&t, now + 1000)); /* wrapped, still within the window */
    CHECK(thermo_tick(&t, now + THERMO_PENDING_MS));
}

static void test_dp_table(void)
{
    CHECK(thermo_dp_check_write(16, 225) == NULL);
    CHECK(thermo_dp_check_write(16, 224) != NULL); /* not a 0.5 step */
    CHECK(thermo_dp_check_write(16, 45) != NULL);
    CHECK(thermo_dp_check_write(16, 405) != NULL);
    CHECK(thermo_dp_check_write(112, -90) == NULL);
    CHECK(thermo_dp_check_write(112, -91) != NULL);
    CHECK(thermo_dp_check_write(114, 3) == NULL);
    CHECK(thermo_dp_check_write(114, 4) != NULL);
    CHECK(thermo_dp_check_write(115, 1) != NULL); /* factory reset: unknown, never writable */
    CHECK(thermo_dp_check_write(121, 300) != NULL);
    CHECK(thermo_dp_check_write(116, 320) != NULL);
    CHECK(thermo_dp_check_write(119, 0) != NULL);
    CHECK(thermo_dp_check_write(107, 0) != NULL);
    CHECK(thermo_dp_find(115) == NULL);
    /* The TuyaMCU core allowlist must permit exactly the writable DPs, and never 115. */
    for (unsigned id = 0; id < 256; id++) {
        const thermo_dp_info *d = thermo_dp_find((uint8_t)id);
        bool writable = d && d->writable;
        if (writable != tm_dp_write_allowed((uint8_t)id)) printf("  DP %u: table %d, allowlist %d\n", id, writable, !writable);
        CHECK(writable == tm_dp_write_allowed((uint8_t)id));
    }
    CHECK(!tm_dp_write_allowed(115));
}

int main(void)
{
    RUN(test_view);
    RUN(test_setpoint_hold);
    RUN(test_setpoint_timeout);
    RUN(test_rewrite_in_flight);
    RUN(test_clamp_round);
    RUN(test_modes);
    RUN(test_unknown_modes);
    RUN(test_wrap);
    RUN(test_dp_table);
    printf("%d checks, %d failed\n", t_checks, t_fails);
    return t_fails != 0;
}
