/* Internal to the tuyamcu lib. */
#ifndef TM_PRIV_H
#define TM_PRIV_H

#include "tuyamcu.h"

enum { ST_DOWN, ST_PRODUCT, ST_MODE, ST_READY };

#define TM_LOG(tm, ...)                                                                            \
    do {                                                                                           \
        if ((tm)->io.log) (tm)->io.log((tm)->io.ctx, __VA_ARGS__);                                 \
    } while (0)

tm_err tm_tx(tuyamcu *tm, uint8_t cmd, const uint8_t *data, size_t len);
void tm_emit(tuyamcu *tm, const tm_event *ev);
void tm_start_init(tuyamcu *tm);
void tm_push_net_status(tuyamcu *tm);
void tm_answer_net_query(tuyamcu *tm);
void tm_dispatch(tuyamcu *tm, const tm_frame *f); /* tuyamcu_rx.c */

#endif
