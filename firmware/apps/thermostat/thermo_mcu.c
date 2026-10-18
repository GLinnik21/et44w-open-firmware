#include "thermo_mcu.h"

#include "clock.h"
#include "tuyamcu_port.h"

bool thermo_mcu_report(const tm_dp* dp, int32_t* value) {
    if ((dp->type != TM_DP_BOOL && dp->type != TM_DP_VALUE && dp->type != TM_DP_ENUM && dp->type != TM_DP_BITMAP) ||
        !thermo_dp_used(dp->id)) {
        return false;
    }
    *value = tm_dp_i32(dp);
    return true;
}

bool thermo_mcu_write(uint8_t dp, thermo_wtype type, int32_t value) {
    static const uint8_t kType[] = { [THERMO_W_BOOL] = TM_DP_BOOL,
                                     [THERMO_W_VALUE] = TM_DP_VALUE,
                                     [THERMO_W_ENUM] = TM_DP_ENUM };
    return (unsigned) type < sizeof kType && tuyamcu_port_write(dp, kType[type], value);
}

bool thermo_mcu_time(bool local, tm_time* t, void* ctx) {
    (void) ctx;
    return clock_get(local, t);
}
