/* A small node: ACL, Basic Information, General Commissioning, Administrator Commissioning on
 * endpoint 0; Identify, Thermostat and a custom cluster with a long list and a large bytes attribute
 * on endpoint 1. Access: fabric 1 is administrator, fabric 2 may only view, PASE (fabric 0) is admin. */
#include <string.h>
#include "fake_dm.h"

#define L MT_IM_ATTR_LIST
#define W MT_IM_ATTR_WRITABLE
#define T MT_IM_ATTR_TIMED_WRITE
#define F MT_IM_ATTR_FIXED
#define V MT_IM_PRIV_VIEW
#define O MT_IM_PRIV_OPERATE
#define M MT_IM_PRIV_MANAGE
#define A MT_IM_PRIV_ADMINISTER

static const fattr k_attrs[F_NATTR] = {
    { 0, 0x1F, 0x0000, L | W, A, A, 0, K_ACL, 0 },
    { 0, 0x1F, 0xFFFD, F, V, 0, 0, K_UINT, 1 },
    { 0, 0x28, 0x0001, F, V, 0, 1, K_STR, 0 },
    { 0, 0x28, 0x0002, F, V, 0, 1, K_UINT, 0xFFF1 },
    { 0, 0x28, 0x0005, W, V, M, 1, K_STR, 0 },
    { 0, 0x28, 0xFFFD, F, V, 0, 1, K_UINT, 3 },
    { 0, 0x30, 0x0000, W, V, A, 2, K_UINT, 0 },
    { 0, 0x30, 0xFFFD, F, V, 0, 2, K_UINT, 1 },
    { 0, 0x3C, 0x0000, 0, V, 0, 3, K_UINT, 0 },
    { 0, 0x3C, 0xFFFD, F, V, 0, 3, K_UINT, 1 },
    { 1, 0x03, 0x0000, W, V, O, 4, K_UINT, 0 },
    { 1, 0x03, 0xFFFD, F, V, 0, 4, K_UINT, 4 },
    { 1, 0x201, 0x0000, 0, V, 0, 5, K_INT, 2150 },
    { 1, 0x201, 0x0012, W, V, O, 5, K_INT, 2000 },
    { 1, 0x201, 0x001C, W, V, O, 5, K_UINT, 4 },
    { 1, 0x201, 0x0023, W | T, V, O, 5, K_UINT, 0 },
    { 1, 0x201, 0xFFFB, L | F, V, 0, 5, K_LIST, 0 },
    { 1, 0x201, 0xFFFD, F, V, 0, 5, K_UINT, 6 },
    { 1, 0xFFF1FC01, 0x0000, L | W, V, O, 6, K_LIST, 0 },
    { 1, 0xFFF1FC01, 0x0001, 0, V, 0, 6, K_BYTES, 0 },
    { 1, 0xFFF1FC01, 0xFFFD, F, V, 0, 6, K_UINT, 1 },
    { 2, 0x1D, 0x0000, 0, V, 0, 0xFF, K_UINT, 7 }, /* endpoint 2: no data-version filter index */
};

fattr g_attrs[F_NATTR];
uint32_t g_dataver[F_NCL];
uint32_t g_list[F_LIST_MAX];
unsigned g_list_n;
uint8_t g_acl[8];
unsigned g_acl_n;
size_t g_huge_len;
mt_im g_im;
uint32_t g_now;
int g_send_fail;
int g_identify_calls;
sent_t g_sent[128];
int g_nsent;
static uint16_t g_next_exch;
static uint8_t g_tx[1400];
static const uint8_t k_huge[600];

fattr *fake_attr(uint16_t ep, uint32_t cl, uint32_t at)
{
    for (unsigned i = 0; i < F_NATTR; i++)
        if (g_attrs[i].ep == ep && g_attrs[i].cl == cl && g_attrs[i].at == at) return &g_attrs[i];
    return NULL;
}

static mt_err attr_at(void *ctx, uint16_t idx, mt_im_attr *out)
{
    (void)ctx;
    if (idx >= F_NATTR) return MT_ERR_NOT_FOUND;
    const fattr *f = &g_attrs[idx];
    mt_im_attr a = { f->ep, f->cl, f->at, f->cidx < F_NCL ? g_dataver[f->cidx] : 7, f->flags, f->rp, f->wp, f->cidx };
    *out = a;
    return MT_OK;
}

/* Items of a list attribute after fabric filtering: returns the value of item `item` or -1. */
static int64_t list_item(const fattr *f, const mt_im_rctx *rc, uint16_t item)
{
    if (f->kind == K_ACL) {
        unsigned n = 0;
        for (unsigned i = 0; i < g_acl_n; i++) {
            if (rc->fabric_filtered && g_acl[i] != rc->subj->fabric) continue;
            if (n++ == item) return g_acl[i];
        }
        return -1;
    }
    if (f->cl == 0x201) /* AttributeList of the thermostat */
        return item < 6 ? (int64_t)(uint32_t[]){ 0, 0x12, 0x1C, 0x23, 0xFFFB, 0xFFFD }[item] : (int64_t)-1;
    return item < g_list_n ? (int64_t)g_list[item] : -1;
}

mt_err fake_read(void *ctx, const mt_im_rctx *rc, const mt_im_attr *a, uint16_t item, mt_tlv_wr *w,
                 mt_tlv_tag tag)
{
    (void)ctx;
    const fattr *f = fake_attr(a->endpoint, a->cluster, a->attr);
    if (!f) return MT_ERR_INVALID;
    switch (f->kind) {
    case K_INT: return mt_tlv_put_i(w, tag, f->val);
    case K_UINT: return mt_tlv_put_u(w, tag, (uint64_t)f->val);
    case K_STR: return f->at == 1 ? mt_tlv_put_utf8(w, tag, "TestVendor", 10) : mt_tlv_put_utf8(w, tag, "", 0);
    case K_BYTES: return mt_tlv_put_bytes(w, tag, mt_span_of(k_huge, g_huge_len));
    default: break;
    }
    int64_t v = list_item(f, rc, item);
    if (v < 0) return MT_ERR_NOT_FOUND;
    if (f->kind != K_ACL) return mt_tlv_put_u(w, tag, (uint64_t)v);
    /* AccessControlEntryStruct reduced to {1: privilege, 0xFE: FabricIndex} */
    mt_tlv_mark m = mt_tlv_wr_mark(w);
    mt_err e = mt_tlv_start(w, tag, MT_TLV_STRUCT);
    if (!e) e = mt_tlv_put_u(w, mt_tlv_ctx(1), 5);
    if (!e) e = mt_tlv_put_u(w, mt_tlv_ctx(0xFE), (uint64_t)v);
    if (!e) e = mt_tlv_end(w);
    if (e) mt_tlv_wr_rollback(w, m);
    return e;
}

static void changed(const fattr *f)
{
    g_dataver[f->cidx]++;
    mt_im_mark_dirty(&g_im, f->ep, f->cl, f->at);
}

static mt_err acl_item(mt_tlv_rd *r, uint8_t fabric)
{
    if (r->type != MT_TLV_STRUCT || g_acl_n == sizeof g_acl) return MT_ERR_INVALID;
    g_acl[g_acl_n++] = fabric;
    return MT_OK;
}

static mt_im_status f_write(void *ctx, const mt_im_wctx *wc, const mt_im_attr *a, mt_im_wr_op op, mt_tlv_rd *val)
{
    (void)ctx;
    fattr *f = fake_attr(a->endpoint, a->cluster, a->attr);
    int64_t v;
    uint64_t u;
    if (f->kind == K_ACL || f->kind == K_LIST) {
        if (op == MT_IM_WR_VALUE) {
            if (val->type != MT_TLV_ARRAY) return MT_IM_INVALID_DATA_TYPE;
            mt_tlv_rd r = *val;
            if (f->kind == K_ACL) {
                unsigned keep = 0; /* fabric-scoped: replace only the writer's entries */
                for (unsigned i = 0; i < g_acl_n; i++)
                    if (g_acl[i] != wc->subj->fabric) g_acl[keep++] = g_acl[i];
                g_acl_n = keep;
            } else {
                g_list_n = 0;
            }
            mt_tlv_enter(&r);
            while (!mt_tlv_next(&r)) {
                if (f->kind == K_ACL) {
                    if (acl_item(&r, wc->subj->fabric)) return MT_IM_CONSTRAINT_ERROR;
                } else {
                    if (mt_tlv_get_u64(&r, &u) || g_list_n == F_LIST_MAX) return MT_IM_CONSTRAINT_ERROR;
                    g_list[g_list_n++] = (uint32_t)u;
                }
            }
        } else if (f->kind == K_ACL) {
            if (acl_item(val, wc->subj->fabric)) return MT_IM_CONSTRAINT_ERROR;
        } else {
            if (mt_tlv_get_u64(val, &u) || g_list_n == F_LIST_MAX) return MT_IM_CONSTRAINT_ERROR;
            g_list[g_list_n++] = (uint32_t)u;
        }
        changed(f);
        return MT_IM_SUCCESS;
    }
    if (f->kind == K_STR) return val->type == MT_TLV_UTF8 ? MT_IM_SUCCESS : MT_IM_INVALID_DATA_TYPE;
    if (mt_tlv_get_i64(val, &v)) return MT_IM_INVALID_DATA_TYPE;
    if (f->at == 0x12 && (v < 500 || v > 4000)) return MT_IM_CONSTRAINT_ERROR;
    if (f->val != v) {
        f->val = v;
        changed(f);
    }
    return MT_IM_SUCCESS;
}

static mt_err cmd_info(void *ctx, const mt_im_cmd *c, uint8_t *priv, bool *timed)
{
    (void)ctx;
    *timed = false;
    if (c->cluster == 0x03 && c->command == 0) *priv = MT_IM_PRIV_MANAGE;
    else if (c->cluster == 0x03 && c->command == 0x20) *priv = MT_IM_PRIV_MANAGE; /* answers later */
    else if (c->cluster == 0x30 && c->command == 0) *priv = MT_IM_PRIV_ADMINISTER;
    else if (c->cluster == 0x3C && c->command == 0) *priv = MT_IM_PRIV_ADMINISTER, *timed = true;
    else return MT_ERR_NOT_FOUND;
    return MT_OK;
}

uint16_t g_def_session, g_def_exch;
int g_def_calls, g_hold_calls;

static mt_im_status invoke(void *ctx, const mt_im_subject *s, const mt_im_cmd *c, mt_tlv_rd *fields,
                           mt_tlv_wr *resp, uint32_t *resp_cmd)
{
    (void)ctx;
    if (c->cluster == 0x03 && c->command == 0x20) {
        g_def_session = s->session;
        g_def_exch = mt_im_invoke_exch(&g_im);
        g_def_calls++;
        return MT_IM_DEFER;
    }
    if (c->cluster == 0x03) { /* Identify {0: IdentifyTime} */
        mt_tlv_rd r = *fields;
        uint16_t t;
        if (r.type != MT_TLV_STRUCT || mt_tlv_enter(&r) || mt_tlv_find_ctx(&r, 0) || mt_tlv_get_u16(&r, &t))
            return MT_IM_INVALID_COMMAND;
        g_identify_calls++;
        return MT_IM_SUCCESS;
    }
    if (c->cluster == 0x30) { /* ArmFailSafe -> ArmFailSafeResponse {0: ErrorCode, 1: DebugText} */
        *resp_cmd = 1;
        if (mt_tlv_put_u(resp, mt_tlv_ctx(0), 0) || mt_tlv_put_utf8(resp, mt_tlv_ctx(1), "", 0))
            return MT_IM_RESOURCE_EXHAUSTED;
        return MT_IM_SUCCESS;
    }
    return MT_IM_CST(0x02); /* OpenCommissioningWindow: cluster status 2 (PAKE parameter error) */
}

static bool f_access(void *ctx, const mt_im_subject *s, uint16_t ep, uint32_t cl, uint8_t priv)
{
    (void)ctx;
    (void)ep;
    (void)cl;
    return s->fabric == 2 ? priv <= MT_IM_PRIV_VIEW : true;
}

const mt_im_dm g_dm = { attr_at, fake_read, f_write, cmd_info, invoke, f_access };

static mt_err f_send(void *ctx, uint16_t session, uint16_t *exch, uint8_t opcode, mt_span payload, bool expect)
{
    (void)ctx;
    if (g_send_fail) return MT_ERR_IO;
    if (*exch == MT_IM_NEW_EXCH) *exch = g_next_exch++;
    sent_t *s = &g_sent[g_nsent++ % 128];
    s->session = session;
    s->exch = *exch;
    s->op = opcode;
    s->expect = expect;
    s->len = payload.len;
    memcpy(s->p, payload.p, payload.len);
    return MT_OK;
}

static uint32_t now_ms(void *ctx)
{
    (void)ctx;
    return g_now;
}

static void f_hold(void *ctx, uint16_t exch)
{
    (void)ctx;
    (void)exch;
    g_hold_calls++;
}

const mt_im_ports g_ports = { f_send, now_ms, f_hold };
const mt_im_ports g_ports_nohold = { f_send, now_ms, NULL };

void fake_reset(size_t tx_cap)
{
    memcpy(g_attrs, k_attrs, sizeof g_attrs);
    for (unsigned i = 0; i < F_NCL; i++) g_dataver[i] = 0x2A + i;
    g_list_n = 40;
    for (unsigned i = 0; i < g_list_n; i++) g_list[i] = 0x10000 + i * 0x101;
    g_acl_n = 3;
    g_acl[0] = 1, g_acl[1] = 2, g_acl[2] = 1;
    g_huge_len = 0;
    g_now = 1000;
    g_send_fail = 0;
    g_identify_calls = 0;
    g_def_calls = g_hold_calls = 0;
    g_nsent = 0;
    g_next_exch = 100;
    mt_im_cfg cfg = { &g_dm, NULL, &g_ports, NULL, mt_buf_of(g_tx, tx_cap), 0x12345678, 0x100 };
    mt_im_init(&g_im, &cfg);
}
