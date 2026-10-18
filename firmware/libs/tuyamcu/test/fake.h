/* Fake platform for protocol tests: records transmitted frames and events. */
#ifndef FAKE_H
#define FAKE_H

#include "tuyamcu.h"

#define MAX_TX 32
#define MAX_EV 32
#define MAX_FRAME 64

typedef struct {
    tuyamcu tm;
    uint32_t now;
    bool time_known;
    tm_time time;
    int ntx;
    uint8_t tx_cmd[MAX_TX], tx_ver[MAX_TX], tx_data[MAX_TX][64];
    size_t tx_len[MAX_TX];
    int nev;
    tm_event_type ev_type[MAX_EV];
    uint8_t ev_dpid[MAX_EV], ev_dptype[MAX_EV], ev_arg[MAX_EV];
    uint32_t ev_u32[MAX_EV];
    int nframe; /* on_frame calls, both directions */
    bool frame_tx[MAX_FRAME];
    uint8_t frame_cmd[MAX_FRAME];
    uint16_t frame_len[MAX_FRAME];
} fake;

void fake_init(fake *f);
void fake_inject(fake *f, uint8_t ver, uint8_t cmd, const uint8_t *data, size_t len);
/* Brings the link up and through init (product + mode replies), then clears recorded tx/events. */
void fake_link_up(fake *f);
void fake_clear(fake *f);
int fake_count_cmd(const fake *f, uint8_t cmd);

#endif
