#include "thermostat.h"

#include "HAPPlatformRunLoop+Init.h"

#include "accessory.h"
#include "config.h"
#include "thermo_mcu.h"
#include "thermostat_db.h"
#include "tuyamcu_port.h"

#define WRITE_DEBOUNCE_MS ((HAPTime) 500)  // the Home app slider sends a burst of writes
#define TICK_MS           ((HAPTime) 1000) // pending expiry, resync, network status

static struct {
    HAPAccessoryServerRef* server;
    thermo model;
    HAPPlatformTimerRef debounce;
    bool resync;     // a report or write was dropped: ask the MCU for everything again
    bool ticking;    // Tick's next timer is registered
    uint8_t netSent; // last TM_NET_* status sent to the MCU
} s;

typedef struct {
    uint8_t dp;
    int32_t value;
} Report;

static uint32_t NowMs(void) {
    return (uint32_t) HAPPlatformClockGetCurrent();
}

const thermo* thermostat_model(void) {
    return &s.model;
}

// ----- MCU -> HomeKit

static void EnsureTick(void); // housekeeping below; reports and writes restart it if its timer was lost

static void HandleReport(void* _Nullable context, size_t contextSize) {
    HAPAssert(context && contextSize == sizeof(Report));
    EnsureTick();
    const Report* r = context;
    if (thermo_report(&s.model, r->dp, r->value, NowMs())) {
        thermostat_db_raise_events(s.server);
    }
}

void thermostat_post_report(uint8_t dp, int32_t value) {
    Report r = { .dp = dp, .value = value };
    if (HAPPlatformRunLoopScheduleCallback(HandleReport, &r, sizeof r) != kHAPError_None) {
        s.resync = true; // racy but benign: worst case one extra query
    }
}

// ----- HomeKit -> MCU

static void FlushWrites(HAPPlatformTimerRef timer HAP_UNUSED, void* _Nullable context HAP_UNUSED) {
    s.debounce = 0;
    thermo_write w[THERMO_MAX_WRITES];
    size_t n = thermo_take_writes(&s.model, w, HAPArrayCount(w), NowMs());
    for (size_t i = 0; i < n; i++) {
        HAPLogInfo(&kHAPLog_Default, "write dp %u = %ld", w[i].dp, (long) w[i].value);
        if (!thermo_mcu_write(w[i].dp, (thermo_wtype) w[i].type, w[i].value)) {
            s.resync = true;
        }
    }
}

static void ScheduleWrites(void) {
    if (s.debounce) {
        HAPPlatformTimerDeregister(s.debounce);
        s.debounce = 0;
    }
    if (HAPPlatformTimerRegister(&s.debounce, HAPPlatformClockGetCurrent() + WRITE_DEBOUNCE_MS, FlushWrites, NULL)) {
        FlushWrites(0, NULL);
    }
}

static bool Written(bool ok) {
    EnsureTick();
    if (ok && thermo_has_writes(&s.model)) {
        ScheduleWrites();
    }
    return ok;
}

bool thermostat_set_target_state(uint8_t hk) {
    return Written(thermo_set_target_state(&s.model, hk, NowMs()));
}

bool thermostat_set_target_c(float celsius) {
    return Written(thermo_set_target_c(&s.model, celsius, NowMs()));
}

bool thermostat_set_locked(bool on) {
    return Written(thermo_set_locked(&s.model, on, NowMs()));
}

// ----- Housekeeping

static void UpdateNetStatus(void) {
    uint8_t status = HAPAccessoryServerGetState(s.server) != kHAPAccessoryServerState_Running ? TM_NET_NO_LINK :
                     HAPAccessoryServerIsPaired(s.server)                                       ? TM_NET_PAIRED :
                                                                                                  TM_NET_UNPAIRED;
    if (status != s.netSent && tuyamcu_port_set_net_status(status)) {
        s.netSent = status;
    }
}

static void Tick(HAPPlatformTimerRef timer HAP_UNUSED, void* _Nullable context HAP_UNUSED) {
    HAPPlatformTimerRef next;
    s.ticking = !HAPPlatformTimerRegister(&next, HAPPlatformClockGetCurrent() + TICK_MS, Tick, NULL);
    if (!s.ticking) { // out of heap: the next report or HomeKit write restarts the chain
        HAPLogError(&kHAPLog_Default, "thermostat: tick timer lost");
    }
    if (thermo_tick(&s.model, NowMs())) {
        thermostat_db_raise_events(s.server);
    }
    if (s.resync && tuyamcu_port_query_all()) {
        s.resync = false;
    }
    UpdateNetStatus();
}

static void EnsureTick(void) {
    if (!s.ticking) {
        Tick(0, NULL);
    }
}

void thermostat_init(HAPAccessoryServerRef* server, HAPPlatformKeyValueStoreRef keyValueStore HAP_UNUSED) {
    s.server = server;
    thermo_init(&s.model, &(const thermo_cfg) THERMOSTAT_THERMO_CFG);
    Tick(0, NULL);
}
