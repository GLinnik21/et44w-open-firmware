/* Fake data model and exchange layer for the matter-im host tests. */
#ifndef FAKE_DM_H
#define FAKE_DM_H

#include "mt_im.h"

enum { K_INT, K_UINT, K_STR, K_LIST, K_ACL, K_BYTES };

typedef struct {
    uint16_t ep;
    uint32_t cl, at;
    uint8_t flags, rp, wp, cidx, kind;
    int64_t val;
} fattr;

#define F_NATTR 22
#define F_NCL 7
#define F_LIST_MAX 64

extern fattr g_attrs[F_NATTR];
extern uint32_t g_dataver[F_NCL];
extern uint32_t g_list[F_LIST_MAX];   /* the custom cluster's big list */
extern unsigned g_list_n;
extern uint8_t g_acl[8];             /* ACL entries: fabric index of each */
extern unsigned g_acl_n;
extern size_t g_huge_len;            /* length of the custom bytes attribute */
extern mt_im g_im;
extern uint32_t g_now;
extern int g_send_fail;
extern int g_identify_calls;
extern uint16_t g_def_session, g_def_exch; /* what the deferring command (cluster 3, cmd 0x20) saw */
extern int g_def_calls, g_hold_calls;

typedef struct {
    uint16_t session, exch;
    uint8_t op;
    bool expect;
    size_t len;
    uint8_t p[1400];
} sent_t;
extern sent_t g_sent[128];
extern int g_nsent;

extern const mt_im_dm g_dm;
extern const mt_im_ports g_ports;
extern const mt_im_ports g_ports_nohold;

void fake_reset(size_t tx_cap);
fattr *fake_attr(uint16_t ep, uint32_t cl, uint32_t at);
mt_err fake_read(void *ctx, const mt_im_rctx *rc, const mt_im_attr *a, uint16_t item, mt_tlv_wr *w,
                 mt_tlv_tag tag);

#endif
