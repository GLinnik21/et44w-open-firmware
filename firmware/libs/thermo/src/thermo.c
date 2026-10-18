#include "thermo.h"

#include <string.h>

static const uint8_t kDp[THERMO_S_COUNT] = {
    [THERMO_S_SWITCH] = THERMO_DP_SWITCH,     [THERMO_S_MODE] = THERMO_DP_MODE,
    [THERMO_S_STATE] = THERMO_DP_STATE,       [THERMO_S_SETPOINT] = THERMO_DP_SETPOINT,
    [THERMO_S_CURRENT] = THERMO_DP_CURRENT,   [THERMO_S_FAULT] = THERMO_DP_FAULT,
    [THERMO_S_LOCK] = THERMO_DP_LOCK,
};
static const uint8_t kType[THERMO_S_COUNT] = {
    [THERMO_S_SWITCH] = THERMO_W_BOOL,
    [THERMO_S_MODE] = THERMO_W_ENUM,
    [THERMO_S_SETPOINT] = THERMO_W_VALUE,
    [THERMO_S_LOCK] = THERMO_W_BOOL,
};

static int32_t View(const thermo_slot *s) { return s->pending ? s->want : s->value; }
static int32_t V(const thermo *t, int i) { return View(&t->s[i]); }

/* Everything HomeKit sees, to detect changes. */
typedef struct {
    uint8_t target, current;
    int32_t set, cur;
    bool lock, fault;
} Snapshot;

static Snapshot Snap(const thermo *t)
{
    Snapshot s = {thermo_target_state(t), thermo_current_state(t), thermo_target_tenths(t),
                  thermo_current_tenths(t), thermo_locked(t), thermo_fault(t)};
    return s;
}

static bool Same(const Snapshot *a, const Snapshot *b)
{
    return a->target == b->target && a->current == b->current && a->set == b->set &&
           a->cur == b->cur && a->lock == b->lock && a->fault == b->fault;
}

void thermo_init(thermo *t, const thermo_cfg *cfg)
{
    memset(t, 0, sizeof *t);
    t->cfg = *cfg;
}

static int SlotOf(uint8_t dp)
{
    for (int i = 0; i < THERMO_S_COUNT; i++)
        if (kDp[i] == dp) return i;
    return -1;
}

bool thermo_dp_used(uint8_t dp)
{
    return SlotOf(dp) >= 0;
}

bool thermo_report(thermo *t, uint8_t dp, int32_t value, uint32_t now_ms)
{
    (void)now_ms;
    int i = SlotOf(dp);
    if (i < 0) return false;
    Snapshot before = Snap(t);
    thermo_slot *s = &t->s[i];
    s->known = true;
    s->value = value;
    if (s->pending && value == s->want && !s->dirty) s->pending = s->sent = false;
    Snapshot after = Snap(t);
    return !Same(&before, &after);
}

bool thermo_tick(thermo *t, uint32_t now_ms)
{
    Snapshot before = Snap(t);
    for (int i = 0; i < THERMO_S_COUNT; i++) {
        thermo_slot *s = &t->s[i];
        if (s->pending && !s->dirty && (uint32_t)(now_ms - s->since) >= THERMO_PENDING_MS)
            s->pending = s->sent = false;
    }
    Snapshot after = Snap(t);
    return !Same(&before, &after);
}

bool thermo_ready(const thermo *t)
{
    return t->s[THERMO_S_SWITCH].known && t->s[THERMO_S_MODE].known &&
           t->s[THERMO_S_SETPOINT].known && t->s[THERMO_S_CURRENT].known;
}

uint8_t thermo_target_state(const thermo *t)
{
    if (!V(t, THERMO_S_SWITCH)) return THERMO_HK_OFF;
    int32_t mode = V(t, THERMO_S_MODE);
    if (thermo_auto_supported(t) &&
        (mode == t->cfg.mode_smart ||
         (t->cfg.mode_holiday != THERMO_RAW_UNKNOWN && mode == t->cfg.mode_holiday)))
        return THERMO_HK_AUTO;
    return THERMO_HK_HEAT;
}

uint8_t thermo_current_state(const thermo *t)
{
    if (!t->s[THERMO_S_SWITCH].value) return THERMO_HK_OFF; /* reported state, not pending */
    if (t->cfg.state_heating != THERMO_RAW_UNKNOWN)
        return t->s[THERMO_S_STATE].known && t->s[THERMO_S_STATE].value == t->cfg.state_heating
                   ? THERMO_HK_HEAT
                   : THERMO_HK_OFF;
    return t->s[THERMO_S_CURRENT].value < t->s[THERMO_S_SETPOINT].value ? THERMO_HK_HEAT
                                                                        : THERMO_HK_OFF;
}

int32_t thermo_target_tenths(const thermo *t)
{
    int32_t v = V(t, THERMO_S_SETPOINT);
    return v < THERMO_SET_MIN ? THERMO_SET_MIN : v > THERMO_SET_MAX ? THERMO_SET_MAX : v;
}

int32_t thermo_current_tenths(const thermo *t) { return t->s[THERMO_S_CURRENT].value; }
bool thermo_locked(const thermo *t) { return V(t, THERMO_S_LOCK) != 0; }
bool thermo_fault(const thermo *t) { return t->s[THERMO_S_FAULT].value != 0; }

bool thermo_auto_supported(const thermo *t)
{
    return t->cfg.mode_smart != THERMO_RAW_UNKNOWN && t->cfg.mode_hold != THERMO_RAW_UNKNOWN;
}

static void Want(thermo *t, int i, int32_t v, uint32_t now_ms)
{
    thermo_slot *s = &t->s[i];
    s->pending = true;
    s->want = v;
    s->since = now_ms;
    /* With a write in flight the MCU may still change to the sent value, so the last report
     * doesn't tell what it ends on: write again. */
    s->dirty = !s->known || s->value != v || s->sent || s->dirty;
}

bool thermo_set_target_state(thermo *t, uint8_t hk, uint32_t now_ms)
{
    switch (hk) {
    case THERMO_HK_OFF:
        Want(t, THERMO_S_SWITCH, 0, now_ms);
        return true;
    case THERMO_HK_HEAT:
        Want(t, THERMO_S_SWITCH, 1, now_ms);
        if (t->cfg.mode_hold != THERMO_RAW_UNKNOWN && thermo_target_state(t) != THERMO_HK_HEAT)
            Want(t, THERMO_S_MODE, t->cfg.mode_hold, now_ms);
        return true;
    case THERMO_HK_AUTO:
        if (!thermo_auto_supported(t)) return false;
        Want(t, THERMO_S_SWITCH, 1, now_ms);
        if (thermo_target_state(t) != THERMO_HK_AUTO) /* keep holiday as it is */
            Want(t, THERMO_S_MODE, t->cfg.mode_smart, now_ms);
        return true;
    default:
        return false;
    }
}

bool thermo_set_target_c(thermo *t, float celsius, uint32_t now_ms)
{
    if (!(celsius == celsius)) return false; /* NaN */
    /* Clamp before converting: a float outside int32 (or inf) has no defined conversion. */
    if (celsius < THERMO_SET_MIN / 10.0f) celsius = THERMO_SET_MIN / 10.0f;
    if (celsius > THERMO_SET_MAX / 10.0f) celsius = THERMO_SET_MAX / 10.0f;
    float halves = celsius * 2.0f;
    int32_t tenths = (int32_t)(halves + 0.5f) * 5; /* positive here */
    Want(t, THERMO_S_SETPOINT, tenths, now_ms);
    return true;
}

bool thermo_set_locked(thermo *t, bool on, uint32_t now_ms)
{
    Want(t, THERMO_S_LOCK, on ? 1 : 0, now_ms);
    return true;
}

bool thermo_has_writes(const thermo *t)
{
    for (int i = 0; i < THERMO_S_COUNT; i++)
        if (t->s[i].dirty) return true;
    return false;
}

size_t thermo_take_writes(thermo *t, thermo_write *out, size_t max, uint32_t now_ms)
{
    static const uint8_t order[] = {THERMO_S_SWITCH, THERMO_S_MODE, THERMO_S_SETPOINT, THERMO_S_LOCK};
    size_t n = 0;
    for (size_t k = 0; k < sizeof order && n < max; k++) {
        thermo_slot *s = &t->s[order[k]];
        if (!s->dirty) continue;
        s->dirty = false;
        s->since = now_ms;
        if (s->known && !s->sent && s->value == s->want) { /* already there (e.g. toggled back) */
            s->pending = false;
            continue;
        }
        s->sent = true;
        out[n].dp = kDp[order[k]];
        out[n].type = kType[order[k]];
        out[n].value = s->want;
        n++;
    }
    return n;
}
