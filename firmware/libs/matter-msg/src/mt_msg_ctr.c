#include "mt_msg.h"

#define WINDOW 32
#define TX_START_MASK 0x0FFFFFFFu /* spec 4.6.1.1: random 28-bit start */

void mt_msg_rx_init(mt_msg_rx *rx)
{
    rx->max = 0;
    rx->seen = 0xFFFFFFFFu;
    rx->synced = false;
}

/* Restart the window at `counter`: everything at or below it counts as seen. */
static mt_err resync(mt_msg_rx *rx, uint32_t counter)
{
    rx->max = counter;
    rx->seen = 0xFFFFFFFFu;
    rx->synced = true;
    return MT_OK;
}

/* Marks a counter `behind` (1..WINDOW) below max. */
static mt_err mark_behind(mt_msg_rx *rx, uint32_t behind)
{
    uint32_t bit = 1u << (behind - 1);
    if (rx->seen & bit) return MT_ERR_DUPLICATE;
    rx->seen |= bit;
    return MT_OK;
}

/* Advances max by `ahead` (>= 1); the old max becomes a seen counter inside the window. */
static void advance(mt_msg_rx *rx, uint32_t counter, uint32_t ahead)
{
    if (ahead < WINDOW) rx->seen = (rx->seen << ahead) | (1u << (ahead - 1));
    else if (ahead == WINDOW) rx->seen = 1u << (WINDOW - 1);
    else rx->seen = 0xFFFFFFFFu;
    rx->max = counter;
}

mt_err mt_msg_rx_accept(mt_msg_rx *rx, uint32_t counter, mt_msg_rx_mode mode)
{
    uint32_t fwd, back;
    if (!rx->synced) return resync(rx, counter);
    if (counter == rx->max) return MT_ERR_DUPLICATE;
    if (mode == MT_MSG_RX_SECURE) {
        if (counter > rx->max) { advance(rx, counter, counter - rx->max); return MT_OK; }
        back = rx->max - counter;
    } else {
        fwd = counter - rx->max; /* modular */
        if (fwd <= 0x7FFFFFFFu) { advance(rx, counter, fwd); return MT_OK; }
        back = rx->max - counter;
    }
    if (back <= WINDOW) return mark_behind(rx, back);
    if (mode == MT_MSG_RX_SECURE) return MT_ERR_STALE;
    return resync(rx, counter); /* unsecured peer rebooted with a new random counter */
}

void mt_msg_tx_init(mt_msg_tx *tx, uint32_t random, bool secure)
{
    tx->next = random & TX_START_MASK;
    tx->secure = secure;
    tx->exhausted = false;
}

mt_err mt_msg_tx_next(mt_msg_tx *tx, uint32_t *counter)
{
    if (tx->exhausted) return MT_ERR_STATE;
    *counter = tx->next;
    if (tx->next == 0xFFFFFFFFu && tx->secure) tx->exhausted = true;
    else tx->next++; /* wraps for the unsecured counter */
    return MT_OK;
}
