/* Internal interfaces between the port's files. All functions without a note run in the Matter task. */
#ifndef MTP_PORT_PRIV_H
#define MTP_PORT_PRIV_H

#include "mtp_port.h"
#include <stdio.h>

#include "store_kv.h"

#define MTP_LOG(...) printf("matter: " __VA_ARGS__)

/* ---- task.c: the event queue ---- */
enum { MTP_EV_RX, MTP_EV_CONNECT, MTP_EV_SCAN, MTP_EV_CALL, MTP_EV_IP, MTP_EV_WAKE };
typedef struct {
    uint8_t kind;
    uint8_t slot;                         /* RX: buffer slot */
    uint8_t status;                       /* CONNECT / SCAN: MT_NET_* */
    uint32_t gen;                         /* CONNECT / IP: wifi-sta credential generation */
    void (*fn)(mt_node *n, void *arg);    /* CALL */
    void *arg;
} mtp_event;
bool mtp_post(const mtp_event *e);        /* any task, never blocks */

/* ---- store_dct.c: DCT2 behind store_kv ---- */
/* Two steps, so the safe-mode counter (a port variable) is counted before the node's records are parsed: a fault
 * that recurs while they load (damaged flash) still ends in safe mode. */
mt_err mtp_store_init(void);              /* opens DCT2: port variables only. Before the scheduler or in the task */
mt_err mtp_store_load(void);              /* then the node's records (store_kv); MT_ERR_IO if unusable */
mtp_kv *mtp_store(void);
/* The port's own variables (WIFI, SAFE), written at once. */
mt_err mtp_store_get(unsigned mod, const char *name, mt_buf out, size_t *len);
mt_err mtp_store_set(unsigned mod, const char *name, mt_span val);
mt_err mtp_store_del(unsigned mod, const char *name);

/* ---- boot.c ---- */
uint8_t mtp_boot_reason(void);            /* MT_BOOT_* of this boot */
uint32_t mtp_boot_hold_ms(void);          /* ms to wait before the store is opened (watchdog reset) */
bool mtp_boot_begin(void);                /* counts this boot; true = safe mode (skip the node) */
void mtp_boot_stable(void);               /* MTP_SAFE_STABLE_MS of uptime reached */

/* ---- clock.c / rng.c ---- */
uint32_t mtp_now_ms(void *ctx);
bool mtp_rng_init(void);                  /* mtp_start */
int mtp_entropy(void *ctx, uint8_t *out, size_t len);   /* any task (mutex inside) */

/* ---- udp.c ---- */
#define MTP_UDP_SLOTS 3
typedef struct {
    mt_node_addr from;
    uint16_t len;
    uint8_t buf[MT_XCHG_MAX_FRAME];
} mtp_rx_slot;
bool mtp_udp_start(void);                 /* creates the RX task */
mtp_rx_slot *mtp_udp_slot(uint8_t slot);
void mtp_udp_release(uint8_t slot);
void mtp_udp_send(void *ctx, const mt_node_addr *to, mt_span frame);

/* ---- mdns.c ---- */
void mtp_mdns_changed(void *ctx);         /* mt_node_ports.mdns_changed: ctx = the node */
void mtp_mdns_restart(void);              /* the address changed */

/* ---- netctl.c ---- */
/* mtp_start (main, before the scheduler): starts wifi-sta on app->dev_ssid (if any), independent of the store,
 * so OTA and netlog never depend on DCT2 or the node. */
void mtp_netctl_start(const mtp_app *app);
/* Matter task, after the store opened: switches to the stored WIFI network if there is one. */
void mtp_netctl_load(void);
/* app->dev_rescue: join the development network now (no node: safe mode, store or init failure). */
void mtp_netctl_rescue(const char *why);
/* The BLE commissioning window opened / closed. While it is open the rescue network is left (after a short grace
 * for replies in flight, e.g. RemoveFabric's), so a commissioner sees no network and sends one; after it closed
 * unused, mtp_netctl_poll falls back to the rescue network. */
void mtp_netctl_ble_opened(void);
void mtp_netctl_ble_closed(void);
mt_err mtp_netctl_forget(void);            /* erase the stored network (factory reset) */
const mt_netctl_ops *mtp_netctl_ops(void);
void mtp_netctl_event(mt_node *n, const mtp_event *e);  /* CONNECT / SCAN / IP */
uint32_t mtp_netctl_poll(mt_node *n);     /* connect timeout; ms until the next check */
bool mtp_iface(void *ctx, mt_gendiag_iface *out);

/* ---- ble.c: matter-node's BLE ports over btp-port-ambz2 ---- */
void mtp_ble_init(const mtp_credentials *c);   /* before mt_node_init (which may open the BLE window) */
bool mtp_ble_send(void *ctx, mt_span pkt);
void mtp_ble_close(void *ctx);
void mtp_ble_window(void *ctx, bool open);
void mtp_ble_drain(mt_node *n);               /* BLE events -> mt_node_on_ble */
uint32_t mtp_ble_poll(mtp_kv *kv);            /* the reboot a reopened window asks for; ms until it is due */

/* ---- creds.c ---- */
mt_err mtp_creds_build(const mtp_credentials *in, mt_node_credentials *out);

#endif
