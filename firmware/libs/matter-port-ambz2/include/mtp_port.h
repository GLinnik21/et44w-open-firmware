/* matter-port-ambz2 (L2b): runs a matter-node on the RTL8720CF (AmebaZ2) SDK. The app hands over its credentials
 * and node configuration; the port owns the Matter task, the UDP socket, the mDNS records, the clock, entropy, the
 * Matter store (DCT2 in the `matter` flash region), Network Commissioning over wifi-sta and the boot bookkeeping.
 *
 * Boot order in main():
 *     mtp_boot_capture();      // before netlog_init(), which clears the reset reason
 *     netlog_init(); ota_boot_check(); wdog_start(); wlan_network(); ...
 *     mtp_start(&app);         // instead of wifi_sta_start(): the port owns the station
 *     vTaskStartScheduler();
 * mtp_start starts Wi-Fi on app.dev_ssid at once, independent of the store and the node. The Matter task then
 * (after a watchdog reset: MTP_WDOG_HOLD_MS later) opens the store, applies the safe-mode policy (boot_policy.h),
 * switches Wi-Fi to the stored network if there is one, and, unless in safe mode, runs the node. Safe mode and a
 * failed store keep Wi-Fi (OTA, netlog) up.
 *
 * BLE: the node asks for BLE while its boot window is open (cfg.ble_window_s, e.g. 900 s);
 * the port runs btp-port-ambz2 for it and turns BLE off for good at CommissioningComplete or when the BLE window
 * ends. Node-level store writes wait while a BLE link is up (a flash write stalls the BLE
 * radio's timing). A window that needs BLE after the stack
 * was torn down (the last fabric removed) reboots the device. */
#ifndef MTP_PORT_H
#define MTP_PORT_H

#include "mt_node.h"

#define MTP_UDP_PORT 5540

/* Device attestation and the boot window's PASE verifier. Everything must outlive the port. */
typedef struct {
    mt_span dac, pai, cd;                 /* DER DAC, DER PAI, CMS certification declaration */
    const uint8_t *dac_priv;              /* MT_P256_SCALAR_LEN bytes; used only to sign, inside the port */
    uint16_t vendor_id, product_id;
    const uint8_t *w0;                    /* MT_P256_SCALAR_LEN bytes */
    const uint8_t *l;                     /* MT_P256_POINT_LEN bytes */
    mt_span salt;
    uint32_t iterations;
    uint16_t discriminator;
} mtp_credentials;

typedef struct {
    const mtp_credentials *cred;
    /* The node configuration; the port fills in ports and boot_reason. */
    mt_node_cfg node;
    /* Network to use while none is stored (bench builds); NULL = stay off Wi-Fi until commissioned. */
    const char *dev_ssid, *dev_pass;
    /* true: dev_ssid is only a rescue, so commissioning has to deliver the Wi-Fi network. It is joined when no
     * network is stored and no commissioning can deliver one: the node is commissioned (no window), the BLE window
     * has closed, or the node couldn't start (safe mode). Keeps a failed BLE setup reachable for OTA. */
    bool dev_rescue;
    void *ctx;
    /* Wi-Fi task: an IPv4 address was obtained (e.g. confirm an OTA trial). May be NULL. */
    void (*on_ip)(void *ctx);
    /* Matter task, after mt_node_init succeeded. May be NULL. */
    void (*started)(void *ctx, mt_node *n);
    /* Matter task, every loop: the app's own timers; returns ms until it wants to run again. May be NULL. */
    uint32_t (*poll)(void *ctx, mt_node *n);
    /* Log every IM message (uptime ms, session, opcode, length; never the payload) to the console, for "No Response"
     * debugging. */
    bool im_trace;
} mtp_app;

/* Saves the reset reason; call first thing in main(). Without it the boot counts as power-on. */
void mtp_boot_capture(void);
/* Starts Wi-Fi (always, for any non-NULL app; call once) and creates the Matter task. app must stay valid.
 * false = no Matter task (bad arguments or out of memory); Wi-Fi still runs unless app was NULL. */
bool mtp_start(const mtp_app *app);
/* Runs fn(n, arg) in the Matter task (e.g. an MCU report changing an attribute). Any task, never blocks; false if
 * the queue is full or the node is not running (safe mode, store failure). */
bool mtp_call(void (*fn)(mt_node *n, void *arg), void *arg);
/* Wakes the Matter task so it polls the node and the app now. Any task. */
void mtp_wake(void);
/* The node is running (false before init and in safe mode). */
bool mtp_running(void);
/* BLE commissioning (btp-port-ambz2) is not in the middle of starting its stack: off, up, failed or torn down.
 * The S0 self-check measures the heap only then (BLE costs ~31 KiB, more at init). Any task. */
bool mtp_ble_settled(void);
/* The Matter UDP socket is bound to [::]:MTP_UDP_PORT (self-checks). Any task. */
bool mtp_udp_bound(void);
/* Off Wi-Fi on purpose: nothing stored, the development network is a rescue only, and a BLE window is running (a
 * commissioner must see no network, so it sends one). Self-checks can't expect an IP then. Any task. */
bool mtp_offline_for_ble(void);
/* Factory reset: removes every fabric and the stored Wi-Fi network, then reboots into the boot commissioning window.
 * Any task (runs in the Matter task); false if it couldn't be queued. */
bool mtp_factory_reset(void);

#endif
