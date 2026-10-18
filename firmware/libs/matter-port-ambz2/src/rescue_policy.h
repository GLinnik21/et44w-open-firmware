/* When the development network is a rescue (mtp_app.dev_rescue), pure: netctl.c feeds it its state each poll.
 *
 * Join: nothing stored, no connect pending, no fail-safe armed (a commissioner may still be between ConnectNetwork
 * and CommissioningComplete, which saves its network: the BLE link is often gone by then), no BLE window running,
 * and either the BLE window has closed or there is no commissioning window at all (commissioned without a stored
 * network; safe mode calls netctl_rescue directly).
 * Leave: a BLE window is running (the last fabric went) and nothing is pending, so a commissioner sees no network
 * and sends one; netctl.c waits a short grace first for replies in flight. */
#ifndef MTP_RESCUE_POLICY_H
#define MTP_RESCUE_POLICY_H

#include <stdbool.h>

typedef struct {
    bool mode;          /* app->dev_rescue with a development network */
    bool on;            /* on the rescue network now */
    bool saved;         /* a network is stored */
    bool pending;       /* a ConnectNetwork is waiting for its result */
    bool failsafe;      /* the fail-safe is armed */
    bool ble_open;      /* a BLE commissioning window is running */
    bool ble_closed;    /* a BLE window ran and closed (or BLE failed) */
    bool window_open;   /* any commissioning window is open */
} mtp_rescue_state;

static inline bool mtp_rescue_join(const mtp_rescue_state *s)
{
    return s->mode && !s->on && !s->saved && !s->pending && !s->failsafe && !s->ble_open &&
           (s->ble_closed || !s->window_open);
}

static inline bool mtp_rescue_leave(const mtp_rescue_state *s)
{
    return s->on && s->ble_open && !s->pending;
}

#endif
