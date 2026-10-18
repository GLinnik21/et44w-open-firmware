/* btp-port-ambz2 (L2b): the BLE side of Matter commissioning on the RTL8720CF (AmebaZ2) Realtek BLE stack. Thin
 * glue, no BTP logic (that is matter-btp, run by matter-node in the Matter task):
 *  - GATT service 0xFFF6 with C1 (18EE2EF5-263D-4559-959F-4F9C429F9D11, write with response) and C2 (...9D12,
 *    indicate, CCCD). C3 (additional commissioning data, optional in spec 4.18.3) is not served.
 *  - Advertising (spec 5.4.2.5): flags + service data for 0xFFF6: opcode 0, version 0 / 12-bit discriminator (LE16),
 *    vendor id, product id, additional-data flag 0. 20-60 ms for the first 30 s, then 150-1200 ms (spec 5.4.2.5.6),
 *    restarted fast after a disconnect. One link, no pairing.
 *  - A BLE task (priority above the Matter task) owns every Realtek call; the Matter task talks to it through
 *    requests (btpp_advertise / btpp_send / btpp_disconnect / btpp_stop) and drains its events with btpp_next.
 *  - Events go through a ring drained by btpp_next. A full ring drops the link (or refuses a new one); its last slot is
 *    kept for DISCONNECTED, so every CONNECTED the consumer saw is followed by a DISCONNECTED.
 *  - The stack is started once (btpp_start) and stopped for good (btpp_stop: bte_deinit). Realtek's deinit does not
 *    return all of its heap (~2.4 KiB measured), so a stopped port never restarts: the caller reboots instead.
 * Everything except notify runs in the caller's (Matter) task. */
#ifndef BTP_PORT_H
#define BTP_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BTPP_DATA_MAX 244   /* largest C1 write: ATT MTU 247 - 3 */

typedef enum {
    BTPP_OFF,        /* never started */
    BTPP_STARTING,   /* BLE task waiting for Wi-Fi / the stack (a stack that never gets READY stays here) */
    BTPP_READY,      /* stack up */
    BTPP_FAILED,     /* start failed (no memory for the task, bte_init or gap_start_bt_stack false); final */
    BTPP_STOPPED,    /* torn down; never restarts */
} btpp_state;

enum {
    BTPP_EV_CONNECTED,
    BTPP_EV_MTU,          /* val = ATT MTU */
    BTPP_EV_SUBSCRIBED,   /* C2 CCCD: indications on */
    BTPP_EV_UNSUBSCRIBED,
    BTPP_EV_WRITE,        /* data[0..len) written on C1 */
    BTPP_EV_SENT,         /* the indication from btpp_send: val 0 = confirmed, else failed */
    BTPP_EV_DISCONNECTED,
};

typedef struct {
    uint8_t kind;
    uint16_t val;
    uint16_t len;
    uint8_t data[BTPP_DATA_MAX];
} btpp_event;

typedef struct {
    uint16_t discriminator, vendor_id, product_id;
    /* BLE task: events are waiting (wake the consumer). May be NULL (the consumer then only polls). */
    void (*notify)(void);
} btpp_cfg;

/* Starts the BLE task (stack init after Wi-Fi is up); advertising begins with btpp_advertise(true). false if it was
 * started before (also after btpp_stop) or the task could not be created. cfg is copied. */
bool btpp_start(const btpp_cfg *cfg);
btpp_state btpp_get_state(void);
/* Advertise (fast phase first) or stop advertising; a connection is not affected. Queued until the stack is up. */
void btpp_advertise(bool on);
/* Indicates pkt on C2 (copied). One at a time: false while the previous one has no BTPP_EV_SENT yet, or if not
 * connected / not running. true = BTPP_EV_SENT follows, unless the link drops first (BTPP_EV_DISCONNECTED then
 * ends it, without a SENT). */
bool btpp_send(const uint8_t *pkt, size_t len);
/* Drops the connection (BTPP_EV_DISCONNECTED follows). */
void btpp_disconnect(void);
/* Stops advertising, drops a connection and deinitializes the stack; waits at most 5 s. Pending events are
 * discarded. true = the radio is off (also: never started, start FAILED, or already stopped). false = the BLE task
 * did not acknowledge within 5 s (stack not READY yet, a link that does not drop): nothing is deleted or
 * deinitialized under it, the state becomes STOPPED and the stack stays allocated, and it may still advertise or
 * hold a link. Then the caller must not write flash; it reboots instead (matter-port-ambz2 ble.c does at once,
 * without flushing deferred kv writes). Later calls return false too. A stack that never reaches READY therefore
 * costs a reboot whenever a window closes. */
bool btpp_stop(void);
/* Next event, or false if none. */
bool btpp_next(btpp_event *out);

#endif
