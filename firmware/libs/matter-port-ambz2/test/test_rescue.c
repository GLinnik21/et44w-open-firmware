/* Host tests of rescue_policy.h: the development network as a rescue (mtp_app.dev_rescue). */
#include <stdio.h>

#include "rescue_policy.h"

static int *F;
#define CHECK(c) do { if (!(c)) { (*F)++; fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); } } while (0)

void test_rescue(int *fails)
{
    mtp_rescue_state s = { .mode = true };
    F = fails;

    /* uncommissioned boot: window open, BLE running -> stay off Wi-Fi */
    s.window_open = true;
    s.ble_open = true;
    CHECK(!mtp_rescue_join(&s) && !mtp_rescue_leave(&s));

    /* BLE commissioning: armed, ConnectNetwork pending, then OK; the phone leaves BLE before CommissioningComplete */
    s.failsafe = true;
    s.pending = true;
    CHECK(!mtp_rescue_join(&s));
    s.pending = false;
    s.ble_open = false;
    s.ble_closed = true;
    CHECK(!mtp_rescue_join(&s));             /* the review's case: no rescue between connect and commit */
    /* CommissioningComplete: network saved, fail-safe disarmed, window closed */
    s.saved = true;
    s.failsafe = false;
    s.window_open = false;
    CHECK(!mtp_rescue_join(&s));

    /* same, but the fail-safe expires instead: revert erased the network -> rescue */
    s.saved = false;
    s.window_open = true;
    CHECK(mtp_rescue_join(&s));

    /* BLE window timed out without any PASE */
    s = (mtp_rescue_state){ .mode = true, .window_open = true, .ble_closed = true };
    CHECK(mtp_rescue_join(&s));

    /* commissioned (no window) without a stored network: rescue at once; then the last fabric goes -> BLE -> leave */
    s = (mtp_rescue_state){ .mode = true };
    CHECK(mtp_rescue_join(&s));
    s.on = true;
    CHECK(!mtp_rescue_join(&s) && !mtp_rescue_leave(&s));
    s.window_open = true;
    s.ble_open = true;
    CHECK(mtp_rescue_leave(&s));
    s.pending = true;
    CHECK(!mtp_rescue_leave(&s));            /* a commissioner's connect owns the station */

    /* bench mode (dev network from boot) and units without a development network never rescue */
    s = (mtp_rescue_state){ .mode = false, .ble_closed = true };
    CHECK(!mtp_rescue_join(&s));
    s.on = true;
    s.ble_open = true;
    s.mode = false;
    s.on = false;
    CHECK(!mtp_rescue_leave(&s));
}
