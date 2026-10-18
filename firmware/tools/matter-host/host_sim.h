/* A simulated ET-44W MCU behind libs/thermo for matter-host endpoint 1: it echoes every DP write after
 * MH_SIM_ECHO_MS, switches the relay (DP3) by comparing the room with the setpoint, and lets the room
 * temperature drift (towards the setpoint while heating, towards MH_SIM_AMBIENT otherwise). */
#ifndef MH_SIM_H
#define MH_SIM_H

#include "mt_thermostat.h"

#define MH_SIM_ECHO_MS 150u
#define MH_SIM_DRIFT_MS 10000u   /* one 0.1 C step per period */
#define MH_SIM_AMBIENT 180       /* tenths of a degree C */

typedef struct {
    thermo model;
    mt_thermostat ts;
    mt_dm *dm;                   /* set once the node is up */
    /* the MCU's own state (tenths of a degree C, raw DP values) */
    int32_t sw, mode, setpoint, current, relay;
    bool echo_due;
    uint32_t echo_at, drift_at;
    thermo_write pend[THERMO_MAX_WRITES];
    size_t n_pend;
} mh_sim;

mt_err mh_sim_init(mh_sim *s, uint32_t now);
/* A step change of the room temperature (deterministic test hook): reported to Matter at once. */
void mh_sim_bump(mh_sim *s, int32_t tenths, uint32_t now);
/* Echoes, drift, relay, thermostat tick. Returns ms until it wants to run again. */
uint32_t mh_sim_poll(mh_sim *s, uint32_t now);

#endif
