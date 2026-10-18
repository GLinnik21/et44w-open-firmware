/* Simulated thermostat MCU, see host_sim.h. */
#include <stdio.h>
#include <string.h>

#include "host_port.h"
#include "host_sim.h"

/* raw DP2/DP3 values of the ET-44W (docs/thermostat-firmware.md, data points): holiday 0, smart 1, hold 2; warming 0, heating 1 */
static const thermo_cfg k_cfg = { .mode_hold = 2, .mode_smart = 1, .mode_holiday = 0, .state_heating = 1 };

static uint32_t s_now_ms(void *ctx) { (void)ctx; return mh_now_ms(); }

static void report(mh_sim *s, uint8_t dp, int32_t v, uint32_t now)
{
    thermo_report(&s->model, dp, v, now);
}

static void update_relay(mh_sim *s, uint32_t now)
{
    int32_t relay = s->sw && s->current < s->setpoint;
    if (relay != s->relay) {
        s->relay = relay;
        report(s, THERMO_DP_STATE, relay, now);
    }
}

static void sync(mh_sim *s)
{
    if (s->dm) mt_thermostat_sync(&s->ts, s->dm);
}

static void on_write(void *ctx)
{
    mh_sim *s = ctx;
    uint32_t now = mh_now_ms();
    size_t first = s->n_pend;
    s->n_pend += thermo_take_writes(&s->model, s->pend + first, THERMO_MAX_WRITES - first, now);
    for (size_t i = first; i < s->n_pend; i++)
        printf("sim: DP%u <- %ld\n", s->pend[i].dp, (long)s->pend[i].value);
    fflush(stdout);
    /* the echo comes MH_SIM_ECHO_MS after the first pending write; later writes join it, they do not push it out
     * (a steady stream of writes would otherwise never be echoed) */
    if (!s->echo_due && s->n_pend > 0) {
        s->echo_due = true;
        s->echo_at = now + MH_SIM_ECHO_MS;
    }
}

mt_err mh_sim_init(mh_sim *s, uint32_t now)
{
    mt_thermostat_cfg c;
    memset(s, 0, sizeof *s);
    thermo_init(&s->model, &k_cfg);
    s->sw = 1; s->mode = 2; s->setpoint = 210; s->current = 200; s->relay = -1;
    report(s, THERMO_DP_SWITCH, s->sw, now);
    report(s, THERMO_DP_MODE, s->mode, now);
    report(s, THERMO_DP_SETPOINT, s->setpoint, now);
    report(s, THERMO_DP_CURRENT, s->current, now);
    report(s, THERMO_DP_FAULT, 0, now);
    update_relay(s, now);
    s->drift_at = now + MH_SIM_DRIFT_MS;
    memset(&c, 0, sizeof c);
    c.model = &s->model;
    c.ctx = s;
    c.now_ms = s_now_ms;
    c.on_write = on_write;
    c.identify_type = MT_IDENTIFY_TYPE_NONE;
    return mt_thermostat_init(&s->ts, &c);
}

void mh_sim_bump(mh_sim *s, int32_t tenths, uint32_t now)
{
    s->current += tenths;
    printf("sim: room %ld.%ld C\n", (long)(s->current / 10), (long)(s->current % 10));
    fflush(stdout);
    report(s, THERMO_DP_CURRENT, s->current, now);
    update_relay(s, now);
    sync(s);
}

uint32_t mh_sim_poll(mh_sim *s, uint32_t now)
{
    uint32_t next, t;
    if (s->echo_due && (int32_t)(now - s->echo_at) >= 0) {
        s->echo_due = false;
        for (size_t i = 0; i < s->n_pend; i++) {
            const thermo_write *w = &s->pend[i];
            if (w->dp == THERMO_DP_SWITCH) s->sw = w->value;
            else if (w->dp == THERMO_DP_MODE) s->mode = w->value;
            else if (w->dp == THERMO_DP_SETPOINT) s->setpoint = w->value;
            else continue;
            report(s, w->dp, w->value, now);   /* the MCU echoes what it took */
        }
        s->n_pend = 0;
        update_relay(s, now);
        sync(s);
    }
    if ((int32_t)(now - s->drift_at) >= 0) {
        int32_t target = s->relay > 0 ? s->setpoint : MH_SIM_AMBIENT;
        s->drift_at = now + MH_SIM_DRIFT_MS;
        if (s->current != target) {
            s->current += s->current < target ? 1 : -1;
            report(s, THERMO_DP_CURRENT, s->current, now);
            update_relay(s, now);
            sync(s);
        }
    }
    next = s->drift_at - now;
    if (s->echo_due) { t = (int32_t)(s->echo_at - now) > 0 ? s->echo_at - now : 0; if (t < next) next = t; }
    if (s->dm) { t = mt_thermostat_tick(&s->ts, s->dm); if (t < next) next = t; }
    return next;
}
