/* Host tests for matter-im.
 * Golden vectors:
 *  - connectedhomeip src/app/tests/TestAttributeValueEncoder.cpp (master, fetched 2026-10-18): the
 *    AttributeReportIB byte strings below are copied verbatim, including the list-chunking sequences
 *    with 28/30/60-byte buffers. The harness mirrors chip's: an open anonymous struct + AttributeReportIBs
 *    array, and two bytes held back for closing them.
 *  - Whole IM messages (ReportData, StatusResponse, SubscribeResponse, WriteResponse, InvokeResponse)
 *    are hand-assembled from the tag tables of Matter 1.3 section 10.6/10.7 (tag numbers cross-checked
 *    against rs-matter src/im/encoding); IM revision 11 as chip's v1.3-branch.
 * Everything else drives the engine with a fake data model (fake_dm.c) and a fake clock. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fake_dm.h"
#include "im_priv.h"

static int g_fail, g_checks;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define BYTES(...) ((const uint8_t[]){ __VA_ARGS__ })
#define SAME(p, n, ...) ((n) == sizeof(BYTES(__VA_ARGS__)) && !memcmp((p), BYTES(__VA_ARGS__), (n)))
#define LAST (&g_sent[(g_nsent - 1) % 128])

static const mt_im_subject k_admin = { 1, MT_IM_AUTH_CASE, 1, 0x1111 };
static const mt_im_subject k_viewer = { 2, MT_IM_AUTH_CASE, 2, 0x2222 };
static const mt_im_subject k_admin2 = { 3, MT_IM_AUTH_CASE, 1, 0x1111 }; /* same peer, new session */

static void dump(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x%s", p[i], i + 1 < n ? " " : "\n");
}

/* ======================= chip AttributeValueEncoder vectors ======================= */

static const bool k_bools[] = { true, false, false, true, true, false };
static unsigned g_nbools;
static int g_vec_fabric_items; /* 1: the AccessControlExtension list with fabrics 1, 2, 3 */

static mt_err vec_read(void *ctx, const mt_im_rctx *rc, const mt_im_attr *a, uint16_t item, mt_tlv_wr *w,
                       mt_tlv_tag tag)
{
    (void)ctx;
    (void)a;
    if (g_vec_fabric_items) {
        unsigned n = 0;
        for (unsigned f = 1; f <= 3; f++) {
            if (rc->fabric_filtered && f != rc->subj->fabric) continue;
            if (n++ != item) continue;
            mt_tlv_mark m = mt_tlv_wr_mark(w);
            mt_err e = mt_tlv_start(w, tag, MT_TLV_STRUCT);
            if (!e) e = mt_tlv_put_bytes(w, mt_tlv_ctx(1), mt_span_of(NULL, 0));
            if (!e) e = mt_tlv_put_u(w, mt_tlv_ctx(0xFE), f);
            if (!e) e = mt_tlv_end(w);
            if (e) mt_tlv_wr_rollback(w, m);
            return e;
        }
        return MT_ERR_NOT_FOUND;
    }
    return item < g_nbools ? mt_tlv_put_bool(w, tag, k_bools[item]) : MT_ERR_NOT_FOUND;
}

static const mt_im_dm k_vec_dm = { NULL, vec_read, NULL, NULL, NULL, NULL };
static const mt_im_attr k_vec_attr = { 0x55, 0xaa, 0xcc, 0x99, MT_IM_ATTR_LIST, 1, 0, 0 };

typedef struct { uint8_t buf[1024]; mt_tlv_wr w; } vec_setup;

static void vec_init(vec_setup *s, size_t n)
{
    mt_tlv_wr_init(&s->w, mt_buf_of(s->buf, n));
    mt_tlv_start(&s->w, ANON, MT_TLV_STRUCT);
    mt_tlv_start(&s->w, CTX(1), MT_TLV_ARRAY);
    s->w.reserve = 2; /* chip's TLVWriter reserves the two closing bytes of the test overhead */
}

#define HDR 0x15, 0x36, 0x01, 0x15, 0x35, 0x01, 0x24, 0x00, 0x99, 0x37, 0x01, 0x24, 0x02, 0x55, 0x24, 0x03, 0xaa, 0x24, 0x04, 0xcc
#define ITEM(v) 0x15, 0x35, 0x01, 0x24, 0x00, 0x99, 0x37, 0x01, 0x24, 0x02, 0x55, 0x24, 0x03, 0xaa, 0x24, 0x04, 0xcc, \
                0x34, 0x05, 0x18, (v) ? 0x29 : 0x28, 0x02, 0x18, 0x18

static int vec_enc(vec_setup *s, size_t n, uint16_t *item, uint8_t *mode, mt_im_subject *subj, bool ff)
{
    mt_im_rctx rc = { subj, ff };
    vec_init(s, n);
    return im_enc_attr(&k_vec_dm, NULL, &s->w, &rc, &k_vec_attr, item, mode, s->w.len == 3);
}

#define VEC_MATCH(s, ...) do { bool ok_ = SAME((s).buf, (s).w.len, __VA_ARGS__); CHECK(ok_); \
    if (!ok_) dump((s).buf, (s).w.len); } while (0)

static void test_chip_vectors(void)
{
    static vec_setup s;
    mt_im_subject subj = { 0, MT_IM_AUTH_PASE, 0, 1 };
    uint16_t item = 0;
    uint8_t mode = 0;

    /* TestEncodeListOfBools2 */
    g_vec_fabric_items = 0;
    g_nbools = 2;
    CHECK(vec_enc(&s, 1024, &item, &mode, &subj, false) == ENC_DONE);
    VEC_MATCH(s, HDR, 0x18, 0x36, 0x02, 0x09, 0x08, 0x18, 0x18, 0x18);

    /* TestEncodeEmptyList1 */
    g_nbools = 0;
    CHECK(vec_enc(&s, 1024, &item, &mode, &subj, false) == ENC_DONE);
    VEC_MATCH(s, HDR, 0x18, 0x36, 0x02, 0x18, 0x18, 0x18);

    /* TestEncodeFabricScoped: fabric 1, filtered: only the entry of fabric 1 */
    g_vec_fabric_items = 1;
    subj.fabric = 1;
    subj.auth = MT_IM_AUTH_CASE;
    CHECK(vec_enc(&s, 1024, &item, &mode, &subj, true) == ENC_DONE);
    VEC_MATCH(s, HDR, 0x18, 0x36, 0x02, 0x15, 0x30, 0x01, 0x00, 0x24, 0xFE, 0x01, 0x18, 0x18, 0x18, 0x18);
    g_vec_fabric_items = 0;

    /* TestEncodeListChunking: 30, 30, 1024 bytes */
    g_nbools = 6;
    CHECK(vec_enc(&s, 30, &item, &mode, &subj, true) == ENC_PARTIAL);
    VEC_MATCH(s, HDR, 0x18, 0x36, 0x02, 0x09, 0x08, 0x18, 0x18, 0x18);
    CHECK(mode == 1 && item == 2);
    CHECK(vec_enc(&s, 30, &item, &mode, &subj, false) == ENC_PARTIAL);
    VEC_MATCH(s, 0x15, 0x36, 0x01, ITEM(0));
    CHECK(vec_enc(&s, 1024, &item, &mode, &subj, false) == ENC_DONE);
    VEC_MATCH(s, 0x15, 0x36, 0x01, ITEM(1), ITEM(1), ITEM(0));
    CHECK(mode == 0 && item == 0);

    /* TestEncodeListChunking2: 28 (empty array), 30, 60, 1024 bytes */
    CHECK(vec_enc(&s, 28, &item, &mode, &subj, true) == ENC_PARTIAL);
    VEC_MATCH(s, HDR, 0x18, 0x36, 0x02, 0x18, 0x18, 0x18);
    CHECK(vec_enc(&s, 30, &item, &mode, &subj, false) == ENC_PARTIAL);
    VEC_MATCH(s, 0x15, 0x36, 0x01, ITEM(1));
    CHECK(vec_enc(&s, 60, &item, &mode, &subj, false) == ENC_PARTIAL);
    VEC_MATCH(s, 0x15, 0x36, 0x01, ITEM(0), ITEM(0));
    CHECK(vec_enc(&s, 1024, &item, &mode, &subj, false) == ENC_DONE);
    VEC_MATCH(s, 0x15, 0x36, 0x01, ITEM(1), ITEM(1), ITEM(0));

    /* A list cut is only allowed in an empty chunk: otherwise nothing is written. */
    vec_init(&s, 30);
    mt_im_rctx rc = { &subj, false };
    CHECK(im_enc_attr(&k_vec_dm, NULL, &s.w, &rc, &k_vec_attr, &item, &mode, false) == ENC_NOSPACE);
    CHECK(s.w.len == 3 && mode == 0);
}

/* ======================= request builders and report decoder ======================= */

static uint8_t g_req[1024];

static mt_tlv_wr req_begin(void)
{
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, mt_buf_of(g_req, sizeof g_req));
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    return w;
}

static mt_span req_end(mt_tlv_wr *w)
{
    im_put_rev_end(w);
    return mt_tlv_wr_span(w);
}

static void put_apath(mt_tlv_wr *w, mt_tlv_tag tag, uint16_t ep, uint32_t cl, uint32_t at)
{
    mt_tlv_start(w, tag, MT_TLV_LIST);
    if (ep != MT_IM_WILD_EP) mt_tlv_put_u(w, CTX(2), ep);
    if (cl != MT_IM_WILD_ID) mt_tlv_put_u(w, CTX(3), cl);
    if (at != MT_IM_WILD_ID) mt_tlv_put_u(w, CTX(4), at);
    mt_tlv_end(w);
}

static void rx(const mt_im_subject *s, uint16_t exch, uint8_t op, mt_span p)
{
    mt_im_on_msg(&g_im, s, exch, op, p);
}

static void ack(const mt_im_subject *s, uint16_t exch, uint8_t st)
{
    uint8_t b[] = { 0x15, 0x24, 0x00, st, 0x24, 0xFF, 0x0B, 0x18 };
    rx(s, exch, MT_IM_OP_STATUS, mt_span_of(b, sizeof b));
}

static int status_of(const sent_t *s)
{
    mt_im_status st;
    if (s->op != MT_IM_OP_STATUS || im_parse_status_resp(mt_span_of(s->p, s->len), &st)) return -1;
    return st;
}

/* Read request: n attribute paths given as (ep, cl, at) triples. */
static mt_span read_req(bool fabric_filtered, int n, const uint32_t (*paths)[3])
{
    mt_tlv_wr w = req_begin();
    mt_tlv_start(&w, CTX(0), MT_TLV_ARRAY);
    for (int i = 0; i < n; i++) put_apath(&w, ANON, (uint16_t)paths[i][0], paths[i][1], paths[i][2]);
    mt_tlv_end(&w);
    mt_tlv_put_bool(&w, CTX(3), fabric_filtered);
    return req_end(&w);
}

static uint64_t hash_elem(const mt_tlv_rd *r)
{
    uint64_t h = 1469598103934665603ULL ^ (uint64_t)r->type;
    if (r->type == MT_TLV_UTF8 || r->type == MT_TLV_BYTES) {
        for (size_t i = 0; i < r->str.len; i++) h = (h ^ r->str.p[i]) * 1099511628211ULL;
        return h ^ r->str.len;
    }
    if (!mt_tlv_is_container(r)) return (h ^ r->val) * 1099511628211ULL;
    mt_tlv_rd c = *r;
    mt_tlv_enter(&c);
    while (!mt_tlv_next(&c)) h = (h * 31 + c.tag.num) ^ hash_elem(&c);
    return h;
}

typedef struct {
    bool status, item, list;
    uint8_t st;
    uint16_t ep;
    uint32_t cl, at, ver;
    unsigned n;
    uint64_t h[64];
} rep_t;

typedef struct {
    bool has_sub, more, suppress;
    uint32_t sub;
    int n, nev;
    rep_t r[64];
    uint64_t ev[8];
    uint32_t ev_cl[8];
} rpt_t;

static void dec_path(mt_tlv_rd *p, rep_t *o)
{
    mt_tlv_rd c = *p;
    mt_tlv_enter(&c);
    while (!mt_tlv_next(&c)) {
        if (mt_tlv_is_ctx(&c, 2)) mt_tlv_get_u16(&c, &o->ep);
        if (mt_tlv_is_ctx(&c, 3)) mt_tlv_get_u32(&c, &o->cl);
        if (mt_tlv_is_ctx(&c, 4)) mt_tlv_get_u32(&c, &o->at);
        if (mt_tlv_is_ctx(&c, 5)) o->item = c.type == MT_TLV_NULL;
    }
}

static bool decode_report(const sent_t *s, rpt_t *o)
{
    mt_tlv_rd r;
    memset(o, 0, sizeof *o);
    if (s->op != MT_IM_OP_REPORT) return false;
    mt_tlv_rd_init(&r, mt_span_of(s->p, s->len));
    if (mt_tlv_next(&r) || mt_tlv_enter(&r)) return false;
    while (!mt_tlv_next(&r)) {
        if (mt_tlv_is_ctx(&r, 0)) o->has_sub = !mt_tlv_get_u32(&r, &o->sub);
        if (mt_tlv_is_ctx(&r, 3)) mt_tlv_get_bool(&r, &o->more);
        if (mt_tlv_is_ctx(&r, 4)) mt_tlv_get_bool(&r, &o->suppress);
        if (mt_tlv_is_ctx(&r, 1)) {
            mt_tlv_rd a = r;
            mt_tlv_enter(&a);
            while (!mt_tlv_next(&a)) {
                if (o->n >= 64) break;
                rep_t *x = &o->r[o->n++];
                mt_tlv_rd ib = a;
                mt_tlv_enter(&ib);
                mt_tlv_next(&ib);
                x->status = mt_tlv_is_ctx(&ib, 0);
                mt_tlv_rd f = ib;
                mt_tlv_enter(&f);
                while (!mt_tlv_next(&f)) {
                    if (mt_tlv_is_ctx(&f, 0) && !x->status) mt_tlv_get_u32(&f, &x->ver);
                    if ((mt_tlv_is_ctx(&f, 0) && x->status) || (mt_tlv_is_ctx(&f, 1) && !x->status)) dec_path(&f, x);
                    if (mt_tlv_is_ctx(&f, 1) && x->status) {
                        mt_tlv_rd st = f;
                        mt_tlv_enter(&st);
                        mt_tlv_find_ctx(&st, 0);
                        mt_tlv_get_u8(&st, &x->st);
                    }
                    if (mt_tlv_is_ctx(&f, 2) && !x->status) {
                        if (f.type == MT_TLV_ARRAY && !x->item) {
                            mt_tlv_rd it = f;
                            x->list = true;
                            mt_tlv_enter(&it);
                            while (!mt_tlv_next(&it) && x->n < 64) x->h[x->n++] = hash_elem(&it);
                        } else {
                            x->h[0] = hash_elem(&f);
                            x->n = 1;
                        }
                    }
                }
            }
        }
        if (mt_tlv_is_ctx(&r, 2)) {
            mt_tlv_rd a = r;
            mt_tlv_enter(&a);
            while (!mt_tlv_next(&a)) {
                mt_tlv_rd d = a;
                mt_tlv_enter(&d);
                mt_tlv_find_ctx(&d, 1); /* EventDataIB */
                mt_tlv_enter(&d);
                while (!mt_tlv_next(&d)) {
                    if (mt_tlv_is_ctx(&d, 1)) mt_tlv_get_u64(&d, &o->ev[o->nev]);
                    if (mt_tlv_is_ctx(&d, 0)) {
                        mt_tlv_rd p = d;
                        mt_tlv_enter(&p);
                        mt_tlv_find_ctx(&p, 2);
                        mt_tlv_get_u32(&p, &o->ev_cl[o->nev]);
                    }
                }
                o->nev++;
            }
        }
    }
    return true;
}

/* What a client reassembles: one value per attribute (lists: array + appended items). */
typedef struct {
    bool seen, list;
    unsigned n;
    uint64_t h[64];
    uint32_t ver;
} val_t;
static val_t g_vals[F_NATTR];
static rpt_t g_rpt;

static int attr_index(uint16_t ep, uint32_t cl, uint32_t at)
{
    fattr *f = fake_attr(ep, cl, at);
    return f ? (int)(f - g_attrs) : -1;
}

static void collect(const rpt_t *o)
{
    for (int i = 0; i < o->n; i++) {
        const rep_t *x = &o->r[i];
        int k = attr_index(x->ep, x->cl, x->at);
        if (k < 0 || x->status) continue;
        val_t *v = &g_vals[k];
        if (x->item) {
            CHECK(v->seen && v->list && v->n < 64); /* items only follow the array */
            if (v->n < 64) v->h[v->n++] = x->h[0];
        } else {
            CHECK(!v->seen); /* each attribute once */
            v->seen = true;
            v->list = x->list;
            v->n = x->n;
            memcpy(v->h, x->h, sizeof v->h);
        }
        v->ver = x->ver;
    }
}

/* Expected value of attribute k as the reader of `subj` sees it. */
static bool expect_val(int k, const mt_im_subject *subj, bool ff, const val_t *v)
{
    uint8_t buf[700];
    mt_tlv_wr w;
    mt_tlv_rd r;
    mt_im_rctx rc = { subj, ff };
    const fattr *f = &g_attrs[k];
    mt_im_attr a = { f->ep, f->cl, f->at, 0, f->flags, 0, 0, 0 };
    unsigned n = 0;
    for (uint16_t item = 0;; item++) {
        mt_tlv_wr_init(&w, mt_buf_of(buf, sizeof buf));
        mt_err e = fake_read(NULL, &rc, &a, item, &w, ANON);
        if (e == MT_ERR_NOT_FOUND) break;
        mt_tlv_rd_init(&r, mt_tlv_wr_span(&w));
        mt_tlv_next(&r);
        if (n >= v->n || v->h[n] != hash_elem(&r)) return false;
        n++;
        if (!(f->flags & MT_IM_ATTR_LIST)) break;
    }
    return n == v->n && v->list == !!(f->flags & MT_IM_ATTR_LIST);
}

/* Reads with ack-driven chunking; returns the number of chunks. */
static int read_all(const mt_im_subject *s, uint16_t exch, mt_span req, size_t cap)
{
    int chunks = 0;
    memset(g_vals, 0, sizeof g_vals);
    int before = g_nsent;
    rx(s, exch, MT_IM_OP_READ, req);
    while (g_nsent > before && decode_report(LAST, &g_rpt)) {
        chunks++;
        CHECK(LAST->len <= cap && LAST->exch == exch);
        CHECK(LAST->expect == g_rpt.more);
        CHECK(g_rpt.suppress == !g_rpt.more);
        if (getenv("IMDBG")) {
            printf("chunk %d len %zu more %d:", chunks, LAST->len, g_rpt.more);
            for (int i = 0; i < g_rpt.n; i++)
                printf(" %u/%x/%x%s%s", g_rpt.r[i].ep, (unsigned)g_rpt.r[i].cl, (unsigned)g_rpt.r[i].at,
                       g_rpt.r[i].item ? "+" : "", g_rpt.r[i].list ? "[]" : "");
            printf("\n");
        }
        collect(&g_rpt);
        if (!g_rpt.more || chunks > 200) break;
        before = g_nsent;
        ack(s, exch, 0);
    }
    return chunks;
}

/* ======================= read ======================= */

static void test_read_golden(void)
{
    static const uint32_t p[][3] = { { 1, 0x201, 0 } };
    fake_reset(1200);
    rx(&k_admin, 7, MT_IM_OP_READ, read_req(true, 1, p));
    CHECK(g_nsent == 1 && LAST->op == MT_IM_OP_REPORT && !LAST->expect && LAST->exch == 7);
    bool ok = SAME(LAST->p, LAST->len,
        0x15, 0x36, 0x01,
          0x15, 0x35, 0x01, 0x24, 0x00, 0x2F,                          /* DataVersion 0x2F */
            0x37, 0x01, 0x24, 0x02, 0x01, 0x25, 0x03, 0x01, 0x02, 0x24, 0x04, 0x00, 0x18,
            0x21, 0x02, 0x66, 0x08,                                     /* LocalTemperature 2150 */
          0x18, 0x18,
        0x18, 0x29, 0x04, 0x24, 0xFF, 0x0B, 0x18);                      /* SuppressResponse, rev 11 */
    CHECK(ok);
    if (!ok) dump(LAST->p, LAST->len);
}

static void test_read_errors(void)
{
    static const uint32_t p[][3] = {
        { 9, 0x201, 0 },                  /* no endpoint 9 */
        { 1, 0x0006, 0 },                 /* no OnOff on endpoint 1 */
        { 1, 0x201, 0x77 },               /* no attribute 0x77 */
        { 0, 0x1F, 0 },                   /* ACL attribute: needs Administer */
        { MT_IM_WILD_EP, 0x1F, MT_IM_WILD_ID } /* wildcard: denied ones silently skipped */
    };
    fake_reset(1200);
    read_all(&k_viewer, 8, read_req(false, 5, p), 1200);
    CHECK(g_rpt.n == 5);
    if (g_rpt.n != 5 || !g_rpt.r[2].status) {
        for (int i = 0; i < g_rpt.n; i++)
            printf("  r%d st=%d/%u %u/%x/%x\n", i, g_rpt.r[i].status, g_rpt.r[i].st, g_rpt.r[i].ep,
                   (unsigned)g_rpt.r[i].cl, (unsigned)g_rpt.r[i].at);
        dump(LAST->p, LAST->len);
    }
    CHECK(g_rpt.r[0].status && g_rpt.r[0].st == MT_IM_UNSUPPORTED_ENDPOINT && g_rpt.r[0].ep == 9);
    CHECK(g_rpt.r[1].status && g_rpt.r[1].st == MT_IM_UNSUPPORTED_CLUSTER);
    CHECK(g_rpt.r[2].status && g_rpt.r[2].st == MT_IM_UNSUPPORTED_ATTRIBUTE && g_rpt.r[2].at == 0x77);
    CHECK(g_rpt.r[3].status && g_rpt.r[3].st == MT_IM_UNSUPPORTED_ACCESS);
    CHECK(!g_rpt.r[4].status && g_rpt.r[4].cl == 0x1F && g_rpt.r[4].at == 0xFFFD); /* ACL attr 0 skipped */

    /* Malformed / empty / too many paths -> StatusResponse */
    fake_reset(1200);
    uint8_t junk[] = { 0x15, 0x36, 0x00, 0x99 };
    rx(&k_admin, 9, MT_IM_OP_READ, mt_span_of(junk, sizeof junk));
    CHECK(status_of(LAST) == MT_IM_INVALID_ACTION);
    rx(&k_admin, 9, MT_IM_OP_READ, read_req(false, 0, p));
    CHECK(status_of(LAST) == MT_IM_INVALID_ACTION);
    static uint32_t many[MT_IM_READ_PATHS + 1][3];
    for (int i = 0; i <= MT_IM_READ_PATHS; i++) many[i][0] = 1, many[i][1] = 0x201, many[i][2] = 0;
    rx(&k_admin, 9, MT_IM_OP_READ, read_req(false, MT_IM_READ_PATHS + 1, (const uint32_t(*)[3])many));
    CHECK(status_of(LAST) == MT_IM_RESOURCE_EXHAUSTED);
    rx(&k_admin, 9, 0x42, mt_span_of(junk, 0));
    CHECK(status_of(LAST) == MT_IM_INVALID_ACTION);
}

static void check_all_values(const mt_im_subject *s, bool ff, int expect_n)
{
    int seen = 0;
    for (int k = 0; k < F_NATTR; k++) {
        if (!g_vals[k].seen) continue;
        seen++;
        bool ok = expect_val(k, s, ff, &g_vals[k]);
        CHECK(ok);
        if (!ok) printf("  attr %d (%x/%x) n=%u\n", k, (unsigned)g_attrs[k].cl, (unsigned)g_attrs[k].at, g_vals[k].n);
    }
    CHECK(seen == expect_n);
    if (seen != expect_n) {
        printf("  seen %d expected %d, missing:", seen, expect_n);
        for (int k = 0; k < F_NATTR; k++) if (!g_vals[k].seen) printf(" %d", k);
        printf("\n");
    }
}

static void test_wildcard_chunked(void)
{
    static const uint32_t all[][3] = { { MT_IM_WILD_EP, MT_IM_WILD_ID, MT_IM_WILD_ID } };
    /* Reference: one big chunk. */
    fake_reset(1400);
    CHECK(read_all(&k_admin, 10, read_req(false, 1, all), 1400) == 1);
    check_all_values(&k_admin, false, F_NATTR);
    CHECK(g_vals[0].n == 3 && g_vals[18].n == 40);

    /* Tiny buffers: the 40-item list goes out as array + items, every chunk within the cap. */
    static const size_t caps[] = { 64, 90, 128, 200 };
    for (unsigned i = 0; i < sizeof caps / sizeof caps[0]; i++) {
        fake_reset(caps[i]);
        int n = read_all(&k_admin, 11, read_req(false, 1, all), caps[i]);
        CHECK(n > 1 && n < 200);
        if (!(n > 1 && n < 200)) printf("  cap %zu: %d chunks, last op %u st %d\n", caps[i], n, LAST->op, status_of(LAST));
        check_all_values(&k_admin, false, F_NATTR);
        CHECK(g_im.reads[0].q.state == Q_FREE && g_im.reads[1].q.state == Q_FREE);
    }

    /* Fabric-filtered read of ACL entries: only fabric 1's two. */
    fake_reset(90);
    static const uint32_t acl[][3] = { { 0, 0x1F, 0 } };
    read_all(&k_admin, 12, read_req(true, 1, acl), 90);
    CHECK(g_vals[0].seen && g_vals[0].n == 2);
    check_all_values(&k_admin, true, 1);

    /* An attribute larger than a whole chunk is skipped, the read still terminates. */
    fake_reset(128);
    g_huge_len = 300;
    int n = read_all(&k_admin, 13, read_req(false, 1, all), 128);
    CHECK(n > 1 && n < 200 && !g_rpt.more);
    CHECK(!g_vals[19].seen);
    check_all_values(&k_admin, false, F_NATTR - 1);
}

static void test_wildcard_flags(void)
{
    mt_tlv_wr w = req_begin();
    mt_tlv_start(&w, CTX(0), MT_TLV_ARRAY);
    mt_tlv_start(&w, ANON, MT_TLV_LIST);
    mt_tlv_put_u(&w, CTX(6), MT_IM_WF_SKIP_ROOT | MT_IM_WF_SKIP_GLOBAL | MT_IM_WF_SKIP_CUSTOM);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    fake_reset(1400);
    read_all(&k_admin, 14, req_end(&w), 1400);
    int seen = 0;
    for (int k = 0; k < F_NATTR; k++) seen += g_vals[k].seen;
    /* endpoint 1 Identify 0, Thermostat 0/12/1C/23, endpoint 2 Descriptor 0 */
    CHECK(seen == 6 && g_vals[10].seen && g_vals[12].seen && g_vals[21].seen && !g_vals[16].seen);
}

static mt_span dv_read_req(uint32_t ver)
{
    mt_tlv_wr w = req_begin();
    mt_tlv_start(&w, CTX(0), MT_TLV_ARRAY);
    put_apath(&w, ANON, 1, MT_IM_WILD_ID, MT_IM_WILD_ID);
    mt_tlv_end(&w);
    mt_tlv_start(&w, CTX(4), MT_TLV_ARRAY);
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_start(&w, CTX(0), MT_TLV_LIST);
    mt_tlv_put_u(&w, CTX(1), 1);
    mt_tlv_put_u(&w, CTX(2), 0x201);
    mt_tlv_end(&w);
    mt_tlv_put_u(&w, CTX(1), ver);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    return req_end(&w);
}

static void test_dataversion_filter(void)
{
    fake_reset(1400);
    read_all(&k_admin, 15, dv_read_req(0x2F), 1400); /* matches: thermostat left out */
    CHECK(g_vals[10].seen && !g_vals[12].seen && !g_vals[17].seen && g_vals[18].seen);
    read_all(&k_admin, 16, dv_read_req(0x2E), 1400); /* stale: thermostat reported */
    CHECK(g_vals[12].seen && g_vals[17].seen && g_vals[12].ver == 0x2F);
}

static void test_read_busy_and_abort(void)
{
    static const uint32_t all[][3] = { { MT_IM_WILD_EP, MT_IM_WILD_ID, MT_IM_WILD_ID } };
    fake_reset(100);
    for (int i = 0; i < MT_IM_N_READS; i++) {
        rx(&k_admin, (uint16_t)(20 + i), MT_IM_OP_READ, read_req(false, 1, all));
        CHECK(LAST->op == MT_IM_OP_REPORT && LAST->expect);
    }
    rx(&k_admin, 30, MT_IM_OP_READ, read_req(false, 1, all));
    CHECK(status_of(LAST) == MT_IM_BUSY);
    ack(&k_admin, 20, MT_IM_FAILURE); /* client aborts */
    CHECK(g_im.reads[0].q.state == Q_FREE);
    mt_im_on_exchange_failed(&g_im, 21);
    CHECK(g_im.reads[1].q.state == Q_FREE);
    rx(&k_admin, 31, MT_IM_OP_READ, read_req(false, 1, all));
    CHECK(LAST->op == MT_IM_OP_REPORT && LAST->expect);
    mt_im_on_session_closed(&g_im, k_admin.session);
    CHECK(g_im.reads[0].q.state == Q_FREE);
}

/* ======================= write ======================= */

typedef struct { uint16_t ep; uint32_t cl, at; int64_t v; int list; int has_ver; uint32_t ver; } wreq;

static mt_span write_req(bool timed, bool more, int n, const wreq *r)
{
    mt_tlv_wr w = req_begin();
    mt_tlv_put_bool(&w, CTX(0), false);
    mt_tlv_put_bool(&w, CTX(1), timed);
    mt_tlv_start(&w, CTX(2), MT_TLV_ARRAY);
    for (int i = 0; i < n; i++) {
        mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
        if (r[i].has_ver) mt_tlv_put_u(&w, CTX(0), r[i].ver);
        mt_tlv_start(&w, CTX(1), MT_TLV_LIST);
        if (r[i].ep != MT_IM_WILD_EP) mt_tlv_put_u(&w, CTX(2), r[i].ep);
        mt_tlv_put_u(&w, CTX(3), r[i].cl);
        mt_tlv_put_u(&w, CTX(4), r[i].at);
        if (r[i].list == 1) mt_tlv_put_null(&w, CTX(5));
        mt_tlv_end(&w);
        if (r[i].list == 2) { /* replace with an array of v items 0..v-1 */
            mt_tlv_start(&w, CTX(2), MT_TLV_ARRAY);
            for (int64_t k = 0; k < r[i].v; k++) mt_tlv_put_u(&w, ANON, (uint64_t)(0x500 + k));
            mt_tlv_end(&w);
        } else {
            mt_tlv_put_i(&w, CTX(2), r[i].v);
        }
        mt_tlv_end(&w);
    }
    mt_tlv_end(&w);
    if (more) mt_tlv_put_bool(&w, CTX(3), true);
    return req_end(&w);
}

/* Statuses of a WriteResponse in order. */
static int write_statuses(const sent_t *s, uint8_t *st, uint32_t *attr)
{
    rpt_t o;
    mt_tlv_rd r;
    int n = 0;
    if (s->op != MT_IM_OP_WRITE_RESP) return -1;
    mt_tlv_rd_init(&r, mt_span_of(s->p, s->len));
    mt_tlv_next(&r);
    mt_tlv_enter(&r);
    mt_tlv_find_ctx(&r, 0);
    mt_tlv_enter(&r);
    while (!mt_tlv_next(&r)) {
        mt_tlv_rd a = r, f;
        memset(&o, 0, sizeof o);
        mt_tlv_enter(&a);
        f = a;
        mt_tlv_find_ctx(&f, 0);
        dec_path(&f, &o.r[0]);
        f = a;
        mt_tlv_find_ctx(&f, 1);
        mt_tlv_enter(&f);
        mt_tlv_find_ctx(&f, 0);
        mt_tlv_get_u8(&f, &st[n]);
        if (attr) attr[n] = o.r[0].at;
        n++;
    }
    return n;
}

static void test_write(void)
{
    uint8_t st[8];
    fake_reset(1200);
    wreq sp = { 1, 0x201, 0x12, 2150, 0, 0, 0 };
    rx(&k_admin, 40, MT_IM_OP_WRITE, write_req(false, false, 1, &sp));
    CHECK(SAME(LAST->p, LAST->len, 0x15, 0x36, 0x00, 0x15, 0x37, 0x00, 0x24, 0x02, 0x01, 0x25, 0x03, 0x01, 0x02,
                0x24, 0x04, 0x12, 0x18, 0x35, 0x01, 0x24, 0x00, 0x00, 0x18, 0x18, 0x18, 0x24, 0xFF, 0x0B, 0x18));
    CHECK(!LAST->expect && fake_attr(1, 0x201, 0x12)->val == 2150 && g_dataver[5] == 0x30);

    /* Apple's control write: SystemMode + setpoint in one request, plus the error paths. */
    wreq many[] = {
        { 1, 0x201, 0x1C, 0, 0, 0, 0 },          /* SystemMode Off */
        { 1, 0x201, 0x12, 9999, 0, 0, 0 },       /* out of range */
        { 1, 0x201, 0x00, 1, 0, 0, 0 },          /* read-only */
        { 1, 0x201, 0x77, 1, 0, 0, 0 },          /* no such attribute */
        { 1, 0x201, 0x12, 2200, 0, 1, 0x01 },    /* stale DataVersion */
        { 1, 0x201, 0x23, 1, 0, 0, 0 },          /* needs a timed write */
    };
    uint32_t at[8];
    rx(&k_admin, 41, MT_IM_OP_WRITE, write_req(false, false, 6, many));
    CHECK(write_statuses(LAST, st, at) == 6);
    CHECK(at[3] == 0x77); /* a failed lookup reports the requested path, not the last attribute it enumerated */
    CHECK(st[0] == MT_IM_SUCCESS && st[1] == MT_IM_CONSTRAINT_ERROR && st[2] == MT_IM_UNSUPPORTED_WRITE);
    CHECK(st[3] == MT_IM_UNSUPPORTED_ATTRIBUTE && st[4] == MT_IM_DATA_VERSION_MISMATCH);
    CHECK(st[5] == MT_IM_NEEDS_TIMED_INTERACTION && fake_attr(1, 0x201, 0x1C)->val == 0);

    /* Viewer may not operate. */
    rx(&k_viewer, 42, MT_IM_OP_WRITE, write_req(false, false, 1, &sp));
    CHECK(write_statuses(LAST, st, NULL) == 1 && st[0] == MT_IM_UNSUPPORTED_ACCESS);

    /* Endpoint wildcard write expands to every endpoint with the attribute. */
    wreq wild = { MT_IM_WILD_EP, 0x03, 0x00, 30, 0, 0, 0 };
    rx(&k_admin, 43, MT_IM_OP_WRITE, write_req(false, false, 1, &wild));
    CHECK(write_statuses(LAST, st, NULL) == 1 && st[0] == 0 && fake_attr(1, 0x03, 0)->val == 30);
}

/* A WriteRequest whose statuses cannot all fit the response is refused before anything is applied. */
static void test_write_overflow(void)
{
    uint8_t st[8];
    wreq four[] = {
        { 1, 0x201, 0x1C, 0, 0, 0, 0 }, { 1, 0x201, 0x12, 2100, 0, 0, 0 },
        { 1, 0x03, 0x00, 7, 0, 0, 0 }, { 1, 0x201, 0x12, 2200, 0, 0, 0 },
    };
    fake_reset(80); /* room for about two statuses */
    rx(&k_admin, 44, MT_IM_OP_WRITE, write_req(false, false, 4, four));
    CHECK(status_of(LAST) == MT_IM_RESOURCE_EXHAUSTED);
    CHECK(fake_attr(1, 0x201, 0x1C)->val == 4 && fake_attr(1, 0x201, 0x12)->val == 2000 &&
          fake_attr(1, 0x03, 0)->val == 0);
    /* the same request fits a full buffer and is applied */
    fake_reset(1200);
    rx(&k_admin, 45, MT_IM_OP_WRITE, write_req(false, false, 4, four));
    CHECK(write_statuses(LAST, st, NULL) == 4 && !st[0] && !st[1] && !st[2] && !st[3]);
    CHECK(fake_attr(1, 0x201, 0x1C)->val == 0 && fake_attr(1, 0x201, 0x12)->val == 2200 &&
          fake_attr(1, 0x03, 0)->val == 7);
    /* a malformed IB after a valid one: nothing applied either */
    fake_reset(1200);
    mt_tlv_wr w = req_begin();
    mt_tlv_put_bool(&w, CTX(0), false);
    mt_tlv_put_bool(&w, CTX(1), false);
    mt_tlv_start(&w, CTX(2), MT_TLV_ARRAY);
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_start(&w, CTX(1), MT_TLV_LIST);
    mt_tlv_put_u(&w, CTX(2), 1);
    mt_tlv_put_u(&w, CTX(3), 0x201);
    mt_tlv_put_u(&w, CTX(4), 0x1C);
    mt_tlv_end(&w);
    mt_tlv_put_u(&w, CTX(2), 0);
    mt_tlv_end(&w);
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT); /* no path */
    mt_tlv_put_u(&w, CTX(2), 0);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    rx(&k_admin, 46, MT_IM_OP_WRITE, req_end(&w));
    CHECK(status_of(LAST) == MT_IM_INVALID_ACTION && fake_attr(1, 0x201, 0x1C)->val == 4);
}

static void test_write_list_chunked(void)
{
    uint8_t st[8];
    fake_reset(1200);
    /* Chunk 1: replace with 3 items, more to come; the exchange stays open. */
    wreq c1 = { 1, 0xFFF1FC01, 0, 3, 2, 0, 0 };
    rx(&k_admin, 50, MT_IM_OP_WRITE, write_req(false, true, 1, &c1));
    CHECK(write_statuses(LAST, st, NULL) == 1 && st[0] == 0 && LAST->expect);
    CHECK(g_list_n == 3 && g_list[2] == 0x502);
    /* Chunk 2: two appends, last chunk. */
    wreq c2[] = { { 1, 0xFFF1FC01, 0, 0x777, 1, 0, 0 }, { 1, 0xFFF1FC01, 0, 0x778, 1, 0, 0 } };
    rx(&k_admin, 50, MT_IM_OP_WRITE, write_req(false, false, 2, c2));
    CHECK(write_statuses(LAST, st, NULL) == 2 && st[0] == 0 && st[1] == 0 && !LAST->expect);
    CHECK(g_list_n == 5 && g_list[3] == 0x777 && g_list[4] == 0x778);
    CHECK(im_xs_find(&g_im, 50) == NULL);

    /* A continuation is bound to the session that began the write: another session on the same exchange number
     * gets its own access check, not the grant cached for the first one's list write. */
    rx(&k_admin, 54, MT_IM_OP_WRITE, write_req(false, true, 1, &c1));
    CHECK(write_statuses(LAST, st, NULL) == 1 && st[0] == 0 && LAST->expect && g_list_n == 3);
    rx(&k_viewer, 54, MT_IM_OP_WRITE, write_req(false, false, 2, c2));
    CHECK(write_statuses(LAST, st, NULL) == 2 && st[0] == MT_IM_UNSUPPORTED_ACCESS &&
          st[1] == MT_IM_UNSUPPORTED_ACCESS && g_list_n == 3);
    rx(&k_admin, 54, MT_IM_OP_WRITE, write_req(false, false, 2, c2));
    CHECK(write_statuses(LAST, st, NULL) == 2 && st[0] == 0 && st[1] == 0 && g_list_n == 5);
    CHECK(im_xs_find(&g_im, 54) == NULL);

    /* Append to a non-list attribute, numeric ListIndex. */
    wreq bad = { 1, 0x201, 0x12, 1, 1, 0, 0 };
    rx(&k_admin, 51, MT_IM_OP_WRITE, write_req(false, false, 1, &bad));
    CHECK(write_statuses(LAST, st, NULL) == 1 && st[0] == MT_IM_INVALID_ACTION);

    /* A chunked write interrupted by another message type is aborted. */
    rx(&k_admin, 52, MT_IM_OP_WRITE, write_req(false, true, 1, &c1));
    CHECK(LAST->expect);
    static const uint32_t p[][3] = { { 1, 0x201, 0 } };
    rx(&k_admin, 52, MT_IM_OP_READ, read_req(false, 1, p));
    CHECK(status_of(LAST) == MT_IM_INVALID_ACTION && im_xs_find(&g_im, 52) == NULL);

    /* Fabric-scoped ACL list write replaces only the writer's own entries. */
    mt_tlv_wr w = req_begin();
    mt_tlv_start(&w, CTX(2), MT_TLV_ARRAY);
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    put_apath(&w, CTX(1), 0, 0x1F, 0);
    mt_tlv_start(&w, CTX(2), MT_TLV_ARRAY);
    mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
    mt_tlv_put_u(&w, CTX(1), 5);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    rx(&k_admin, 53, MT_IM_OP_WRITE, req_end(&w));
    CHECK(write_statuses(LAST, st, NULL) == 1 && st[0] == 0);
    CHECK(g_acl_n == 2 && g_acl[0] == 2 && g_acl[1] == 1);
}

static mt_span timed_req(uint16_t ms)
{
    mt_tlv_wr w = req_begin();
    mt_tlv_put_u(&w, CTX(0), ms);
    return req_end(&w);
}

static void test_timed(void)
{
    uint8_t st[4];
    wreq tw = { 1, 0x201, 0x23, 1, 0, 0, 0 };
    fake_reset(1200);
    /* TimedRequest -> Success (expecting the action), then the timed write. */
    rx(&k_admin, 60, MT_IM_OP_TIMED, timed_req(500));
    CHECK(status_of(LAST) == 0 && LAST->expect);
    CHECK(SAME(LAST->p, LAST->len, 0x15, 0x24, 0x00, 0x00, 0x24, 0xFF, 0x0B, 0x18));
    g_now += 400;
    rx(&k_admin, 60, MT_IM_OP_WRITE, write_req(true, false, 1, &tw));
    CHECK(write_statuses(LAST, st, NULL) == 1 && st[0] == 0 && fake_attr(1, 0x201, 0x23)->val == 1);

    /* Expired window -> UNSUPPORTED_ACCESS. */
    rx(&k_admin, 61, MT_IM_OP_TIMED, timed_req(100));
    g_now += 101;
    rx(&k_admin, 61, MT_IM_OP_WRITE, write_req(true, false, 1, &tw));
    CHECK(status_of(LAST) == MT_IM_UNSUPPORTED_ACCESS);

    /* Flag mismatch both ways -> TIMED_REQUEST_MISMATCH. */
    rx(&k_admin, 62, MT_IM_OP_WRITE, write_req(true, false, 1, &tw));
    CHECK(status_of(LAST) == MT_IM_TIMED_REQUEST_MISMATCH);
    rx(&k_admin, 63, MT_IM_OP_TIMED, timed_req(500));
    rx(&k_admin, 63, MT_IM_OP_WRITE, write_req(false, false, 1, &tw));
    CHECK(status_of(LAST) == MT_IM_TIMED_REQUEST_MISMATCH);

    /* Timed then a Read -> INVALID_ACTION; malformed TimedRequest -> INVALID_ACTION. */
    static const uint32_t p[][3] = { { 1, 0x201, 0 } };
    rx(&k_admin, 64, MT_IM_OP_TIMED, timed_req(500));
    rx(&k_admin, 64, MT_IM_OP_READ, read_req(false, 1, p));
    CHECK(status_of(LAST) == MT_IM_INVALID_ACTION);
    uint8_t junk[] = { 0x15, 0x18 };
    rx(&k_admin, 65, MT_IM_OP_TIMED, mt_span_of(junk, 2));
    CHECK(status_of(LAST) == MT_IM_INVALID_ACTION && !LAST->expect);
    /* A timed window whose exchange dies is released. */
    rx(&k_admin, 66, MT_IM_OP_TIMED, timed_req(500));
    mt_im_on_exchange_failed(&g_im, 66);
    CHECK(im_xs_find(&g_im, 66) == NULL);
}

/* ======================= invoke ======================= */

static mt_span invoke_req(bool timed, int n, uint16_t ep, uint32_t cl, uint32_t cmd, bool fields, int ref)
{
    mt_tlv_wr w = req_begin();
    mt_tlv_put_bool(&w, CTX(0), false);
    mt_tlv_put_bool(&w, CTX(1), timed);
    mt_tlv_start(&w, CTX(2), MT_TLV_ARRAY);
    for (int i = 0; i < n; i++) {
        mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
        mt_tlv_start(&w, CTX(0), MT_TLV_LIST);
        mt_tlv_put_u(&w, CTX(0), ep);
        mt_tlv_put_u(&w, CTX(1), cl);
        mt_tlv_put_u(&w, CTX(2), cmd);
        mt_tlv_end(&w);
        if (fields) {
            mt_tlv_start(&w, CTX(1), MT_TLV_STRUCT);
            mt_tlv_put_u(&w, CTX(0), 10);
            mt_tlv_end(&w);
        }
        if (ref >= 0) mt_tlv_put_u(&w, CTX(2), (uint64_t)ref);
        mt_tlv_end(&w);
    }
    mt_tlv_end(&w);
    return req_end(&w);
}

/* Status in an InvokeResponse's CommandStatusIB, or -1. */
static int invoke_status(const sent_t *s)
{
    mt_tlv_rd r;
    uint8_t st;
    if (s->op != MT_IM_OP_INVOKE_RESP) return -2;
    mt_tlv_rd_init(&r, mt_span_of(s->p, s->len));
    if (mt_tlv_next(&r) || mt_tlv_enter(&r) || mt_tlv_find_ctx(&r, 1) || mt_tlv_enter(&r) || mt_tlv_next(&r) ||
        mt_tlv_enter(&r) || mt_tlv_find_ctx(&r, 1) || mt_tlv_enter(&r) || mt_tlv_find_ctx(&r, 1) ||
        mt_tlv_enter(&r) || mt_tlv_find_ctx(&r, 0) || mt_tlv_get_u8(&r, &st))
        return -1;
    return st;
}

static void test_invoke(void)
{
    fake_reset(1200);
    rx(&k_admin, 70, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0, true, -1));
    CHECK(g_identify_calls == 1 && !LAST->expect);
    CHECK(SAME(LAST->p, LAST->len, 0x15, 0x28, 0x00, 0x36, 0x01, 0x15, 0x35, 0x01,
               0x37, 0x00, 0x24, 0x00, 0x01, 0x24, 0x01, 0x03, 0x24, 0x02, 0x00, 0x18,
               0x35, 0x01, 0x24, 0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x24, 0xFF, 0x0B, 0x18));

    /* Response command (ArmFailSafe -> ArmFailSafeResponse), CommandRef echoed. */
    rx(&k_admin, 71, MT_IM_OP_INVOKE, invoke_req(false, 1, 0, 0x30, 0, true, 7));
    bool ok = SAME(LAST->p, LAST->len, 0x15, 0x28, 0x00, 0x36, 0x01, 0x15, 0x35, 0x00,
               0x37, 0x00, 0x24, 0x00, 0x00, 0x24, 0x01, 0x30, 0x24, 0x02, 0x01, 0x18,
               0x35, 0x01, 0x24, 0x00, 0x00, 0x2C, 0x01, 0x00, 0x18,
               0x24, 0x02, 0x07, 0x18, 0x18, 0x18, 0x24, 0xFF, 0x0B, 0x18);
    CHECK(ok);
    if (!ok) dump(LAST->p, LAST->len);

    rx(&k_admin, 72, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0x40, true, -1));
    CHECK(invoke_status(LAST) == MT_IM_UNSUPPORTED_COMMAND);
    rx(&k_admin, 73, MT_IM_OP_INVOKE, invoke_req(false, 1, 5, 0x03, 0, true, -1));
    CHECK(invoke_status(LAST) == MT_IM_UNSUPPORTED_ENDPOINT);
    rx(&k_admin, 74, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x0006, 0, true, -1));
    CHECK(invoke_status(LAST) == MT_IM_UNSUPPORTED_CLUSTER);
    rx(&k_viewer, 75, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0, true, -1));
    CHECK(invoke_status(LAST) == MT_IM_UNSUPPORTED_ACCESS);
    rx(&k_admin, 76, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0, false, -1));
    CHECK(invoke_status(LAST) == MT_IM_INVALID_COMMAND);
    rx(&k_admin, 77, MT_IM_OP_INVOKE, invoke_req(false, 2, 1, 0x03, 0, true, -1)); /* MaxPathsPerInvoke 1 */
    CHECK(status_of(LAST) == MT_IM_INVALID_ACTION);
    rx(&k_admin, 78, MT_IM_OP_INVOKE, invoke_req(false, 1, 0, 0x3C, 0, true, -1));
    CHECK(invoke_status(LAST) == MT_IM_NEEDS_TIMED_INTERACTION);
    /* Timed invoke; the handler answers with a cluster-specific status. */
    rx(&k_admin, 79, MT_IM_OP_TIMED, timed_req(1000));
    rx(&k_admin, 79, MT_IM_OP_INVOKE, invoke_req(true, 1, 0, 0x3C, 0, true, -1));
    CHECK(invoke_status(LAST) == MT_IM_FAILURE);
    CHECK(LAST->len > 4 && !memcmp(LAST->p + LAST->len - 16, BYTES(0x35, 0x01, 0x24, 0x00, 0x01, 0x24, 0x01, 0x02, 0x18), 9));
}

/* Deferred invoke: the handler returns MT_IM_DEFER, the answer follows through mt_im_invoke_done. */
static void test_invoke_deferred(void)
{
    const uint8_t f[] = { 0x24, 0x00, 0x05 };
    int n;
    fake_reset(1200);
    rx(&k_admin, 80, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0x20, true, 9));
    CHECK(g_nsent == 0 && g_def_calls == 1 && g_hold_calls == 1);
    CHECK(g_def_session == k_admin.session && g_def_exch == 80);
    CHECK(mt_im_invoke_done(&g_im, k_admin.session + 1, 80, MT_IM_SUCCESS, 0x21, mt_span_of(f, sizeof f)) ==
          MT_ERR_NOT_FOUND);
    CHECK(mt_im_invoke_done(&g_im, k_admin.session, 81, MT_IM_SUCCESS, 0x21, mt_span_of(f, sizeof f)) ==
          MT_ERR_NOT_FOUND);
    CHECK(g_nsent == 0);
    CHECK(mt_im_invoke_done(&g_im, k_admin.session, 80, MT_IM_SUCCESS, 0x21, mt_span_of(f, sizeof f)) == MT_OK);
    CHECK(g_nsent == 1 && LAST->exch == 80 && LAST->op == MT_IM_OP_INVOKE_RESP && !LAST->expect);
    bool ok = SAME(LAST->p, LAST->len, 0x15, 0x28, 0x00, 0x36, 0x01, 0x15, 0x35, 0x00,
                   0x37, 0x00, 0x24, 0x00, 0x01, 0x24, 0x01, 0x03, 0x24, 0x02, 0x21, 0x18,
                   0x35, 0x01, 0x24, 0x00, 0x05, 0x18, 0x24, 0x02, 0x09, 0x18, 0x18, 0x18, 0x24, 0xFF, 0x0B, 0x18);
    CHECK(ok);
    if (!ok) dump(LAST->p, LAST->len);
    CHECK(mt_im_invoke_done(&g_im, k_admin.session, 80, MT_IM_SUCCESS, 0x21, mt_span_of(f, sizeof f)) ==
          MT_ERR_NOT_FOUND); /* answered once */

    /* A status answer, with a cluster-specific code. */
    rx(&k_admin, 82, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0x20, true, -1));
    n = g_nsent;
    CHECK(mt_im_invoke_done(&g_im, k_admin.session, 82, MT_IM_CST(0x03), MT_IM_WILD_ID, mt_span_of(NULL, 0)) == MT_OK);
    CHECK(g_nsent == n + 1 && invoke_status(LAST) == MT_IM_FAILURE);
    CHECK(!memcmp(LAST->p + LAST->len - 16, BYTES(0x35, 0x01, 0x24, 0x00, 0x01, 0x24, 0x01, 0x03, 0x18), 9));
    /* Failure with response data given: status wins. */
    rx(&k_admin, 83, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0x20, true, -1));
    CHECK(mt_im_invoke_done(&g_im, k_admin.session, 83, MT_IM_BUSY, 0x21, mt_span_of(f, sizeof f)) == MT_OK);
    CHECK(invoke_status(LAST) == MT_IM_BUSY);

    /* The invoke dies with its exchange, its session, or when the client sends something else on it. */
    rx(&k_admin, 84, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0x20, true, -1));
    mt_im_on_exchange_failed(&g_im, 84);
    CHECK(mt_im_invoke_done(&g_im, k_admin.session, 84, MT_IM_SUCCESS, MT_IM_WILD_ID, mt_span_of(NULL, 0)) ==
          MT_ERR_NOT_FOUND);
    rx(&k_admin, 85, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0x20, true, -1));
    mt_im_on_session_closed(&g_im, k_admin.session);
    CHECK(mt_im_invoke_done(&g_im, k_admin.session, 85, MT_IM_SUCCESS, MT_IM_WILD_ID, mt_span_of(NULL, 0)) ==
          MT_ERR_NOT_FOUND);
    rx(&k_admin, 86, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0x20, true, -1));
    ack(&k_admin, 86, MT_IM_SUCCESS); /* client abandons it */
    CHECK(mt_im_invoke_done(&g_im, k_admin.session, 86, MT_IM_SUCCESS, MT_IM_WILD_ID, mt_span_of(NULL, 0)) ==
          MT_ERR_NOT_FOUND);

    /* Slots: MT_IM_N_DEFER invokes wait, the next is BUSY at once. */
    n = g_nsent;
    for (int i = 0; i < MT_IM_N_DEFER; i++) rx(&k_admin, (uint16_t)(90 + i), MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0x20, true, -1));
    CHECK(g_nsent == n);
    rx(&k_admin, 99, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0x20, true, -1));
    CHECK(g_nsent == n + 1 && invoke_status(LAST) == MT_IM_BUSY);
    CHECK(mt_im_invoke_done(&g_im, k_admin.session, 91, MT_IM_SUCCESS, MT_IM_WILD_ID, mt_span_of(NULL, 0)) == MT_OK);
    CHECK(mt_im_invoke_done(&g_im, k_admin.session, 90, MT_IM_SUCCESS, MT_IM_WILD_ID, mt_span_of(NULL, 0)) == MT_OK);

    /* A response that does not fit in the IM buffer: the client gets RESOURCE_EXHAUSTED, the caller the error. */
    rx(&k_admin, 100, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0x20, true, -1));
    {
        static uint8_t big[2000];
        memset(big, 0x20, sizeof big); /* 0x20 = a TLV unsigned-1 byte element; length alone matters here */
        CHECK(mt_im_invoke_done(&g_im, k_admin.session, 100, MT_IM_SUCCESS, 0x21, mt_span_of(big, sizeof big)) != MT_OK);
        CHECK(status_of(LAST) == MT_IM_RESOURCE_EXHAUSTED);
    }

    /* A node without the hold port cannot defer: FAILURE at once and nothing is left to answer. */
    fake_reset(1200);
    g_im.port = &g_ports_nohold;
    rx(&k_admin, 101, MT_IM_OP_INVOKE, invoke_req(false, 1, 1, 0x03, 0x20, true, -1));
    CHECK(g_nsent == 1 && invoke_status(LAST) == MT_IM_FAILURE);
    CHECK(mt_im_invoke_done(&g_im, k_admin.session, 101, MT_IM_SUCCESS, MT_IM_WILD_ID, mt_span_of(NULL, 0)) ==
          MT_ERR_NOT_FOUND);
}

/* ======================= subscriptions ======================= */

static mt_span sub_req(bool keep, uint16_t floor, uint16_t ceil, bool events, int npaths, uint64_t ev_min)
{
    mt_tlv_wr w = req_begin();
    mt_tlv_put_bool(&w, CTX(0), keep);
    mt_tlv_put_u(&w, CTX(1), floor);
    mt_tlv_put_u(&w, CTX(2), ceil);
    mt_tlv_start(&w, CTX(3), MT_TLV_ARRAY);
    for (int i = 0; i < npaths; i++) put_apath(&w, ANON, MT_IM_WILD_EP, MT_IM_WILD_ID, MT_IM_WILD_ID);
    mt_tlv_end(&w);
    if (events) {
        mt_tlv_start(&w, CTX(4), MT_TLV_ARRAY);
        mt_tlv_start(&w, ANON, MT_TLV_LIST);
        mt_tlv_end(&w);
        mt_tlv_end(&w);
        if (ev_min) {
            mt_tlv_start(&w, CTX(5), MT_TLV_ARRAY);
            mt_tlv_start(&w, ANON, MT_TLV_STRUCT);
            mt_tlv_put_u(&w, CTX(1), ev_min);
            mt_tlv_end(&w);
            mt_tlv_end(&w);
        }
    }
    mt_tlv_put_bool(&w, CTX(7), false);
    return req_end(&w);
}

/* Subscribe and ack every priming chunk; returns the number of priming chunks. */
static int g_prime_nev;
static int subscribe(const mt_im_subject *s, uint16_t exch, mt_span req, size_t cap)
{
    int chunks = 0, before = g_nsent;
    memset(g_vals, 0, sizeof g_vals);
    g_prime_nev = 0;
    rx(s, exch, MT_IM_OP_SUBSCRIBE, req);
    while (g_nsent > before && decode_report(LAST, &g_rpt)) {
        chunks++;
        CHECK(LAST->expect && LAST->exch == exch && LAST->len <= cap && g_rpt.has_sub && !g_rpt.suppress);
        g_prime_nev += g_rpt.nev;
        collect(&g_rpt);
        before = g_nsent;
        ack(s, exch, 0);
        if (chunks > 200) break;
    }
    return chunks;
}

/* Runs a report the engine starts from poll: acks every chunk. Returns chunks, 0 if none. */
static int run_report(const mt_im_subject *s)
{
    int chunks = 0, before = g_nsent;
    memset(g_vals, 0, sizeof g_vals);
    mt_im_poll(&g_im);
    while (g_nsent > before && decode_report(LAST, &g_rpt)) {
        chunks++;
        CHECK(LAST->expect && !g_rpt.suppress);
        collect(&g_rpt);
        before = g_nsent;
        ack(s, LAST->exch, 0);
        if (chunks > 200) break;
    }
    return chunks;
}

static void test_subscribe_priming_liveness(void)
{
    fake_reset(128);
    /* Apple: keep_subs, floor 0, ceiling 600, wildcard attributes. */
    int n = subscribe(&k_admin, 80, sub_req(true, 0, 600, false, 1, 0), 128);
    CHECK(n > 3);
    check_all_values(&k_admin, false, F_NATTR);
    CHECK(LAST->op == MT_IM_OP_SUBSCRIBE_RESP && !LAST->expect && LAST->exch == 80);
    CHECK(SAME(LAST->p, LAST->len, 0x15, 0x26, 0x00, 0x78, 0x56, 0x34, 0x12, 0x25, 0x02, 0x58, 0x02,
               0x24, 0xFF, 0x0B, 0x18));
    CHECK(mt_im_sub_count(&g_im) == 1 && g_im.subs[0].max_s == 600);

    /* Liveness: nothing before 7/8 of MaxInterval, then an empty report on a new exchange. */
    uint32_t wait = mt_im_poll(&g_im);
    CHECK(wait == 525000);
    int before = g_nsent;
    g_now += 524999;
    CHECK(mt_im_poll(&g_im) == 1 && g_nsent == before);
    g_now += 1;
    CHECK(run_report(&k_admin) == 1);
    CHECK(g_rpt.n == 0 && g_rpt.has_sub && g_rpt.sub == 0x12345678);
    CHECK(SAME(LAST->p, LAST->len, 0x15, 0x26, 0x00, 0x78, 0x56, 0x34, 0x12, 0x24, 0xFF, 0x0B, 0x18));
    CHECK(LAST->exch != 80 && LAST->expect);
    CHECK(mt_im_poll(&g_im) == 525000);

    /* Dirty: a write marks the setpoint; with floor 0 the next poll reports just that attribute. */
    wreq sp = { 1, 0x201, 0x12, 1900, 0, 0, 0 };
    rx(&k_admin, 81, MT_IM_OP_WRITE, write_req(false, false, 1, &sp));
    CHECK(run_report(&k_admin) == 1 && g_rpt.n == 1 && g_rpt.r[0].at == 0x12);
    CHECK(mt_im_poll(&g_im) == 525000);
}

static void test_subscribe_dirty_min_interval(void)
{
    fake_reset(400);
    subscribe(&k_admin, 90, sub_req(true, 5, 600, false, 1, 0), 400);
    CHECK(mt_im_sub_count(&g_im) == 1);
    g_now += 1000;
    wreq sp = { 1, 0x201, 0x12, 1900, 0, 0, 0 };
    rx(&k_admin, 91, MT_IM_OP_WRITE, write_req(false, false, 1, &sp));
    CHECK(g_im.subs[0].dirty);
    CHECK(mt_im_poll(&g_im) == 4000); /* min interval 5 s from the SubscribeResponse */
    g_now += 4000;
    CHECK(run_report(&k_admin) == 1);
    CHECK(g_rpt.n == 1 && g_rpt.r[0].cl == 0x201 && g_rpt.r[0].at == 0x12 && g_rpt.r[0].ver == 0x30);
    CHECK(!g_im.subs[0].dirty && g_im.subs[0].q.state == Q_ACTIVE);

    /* Two changes in the same cluster plus one elsewhere: one report with exactly those. */
    g_now += 6000;
    wreq two[] = { { 1, 0x201, 0x1C, 0, 0, 0, 0 }, { 1, 0x03, 0x00, 5, 0, 0, 0 } };
    rx(&k_admin, 92, MT_IM_OP_WRITE, write_req(false, false, 2, two));
    fake_attr(1, 0x201, 0)->val = 2100; /* LocalTemperature changes in the DM */
    g_dataver[5]++;
    mt_im_mark_dirty(&g_im, 1, 0x201, 0);
    CHECK(run_report(&k_admin) == 1 && g_rpt.n == 3);
    CHECK(g_vals[10].seen && g_vals[12].seen && g_vals[14].seen && !g_vals[13].seen);

    /* A change while a report is in flight is reported afterwards, not lost. */
    g_now += 6000;
    mt_im_mark_dirty(&g_im, 1, 0x201, 0x12);
    int before = g_nsent;
    mt_im_poll(&g_im);
    CHECK(g_nsent == before + 1 && g_im.subs[0].q.state == Q_REPORT);
    uint16_t ex = LAST->exch;
    mt_im_mark_dirty(&g_im, 1, 0x201, 0x1C);
    ack(&k_admin, ex, 0);
    CHECK(g_im.subs[0].dirty);
    g_now += 5000;
    CHECK(run_report(&k_admin) == 1 && g_rpt.n == 1 && g_rpt.r[0].at == 0x1C);

    /* Overflow of the dirty set: a full report. */
    g_now += 6000;
    for (uint32_t i = 0; i < MT_IM_N_DIRTY + 2; i++) mt_im_mark_dirty(&g_im, 1, 0x7000 + i, 0);
    CHECK(run_report(&k_admin) >= 1);
    int seen = 0;
    for (int k = 0; k < F_NATTR; k++) seen += g_vals[k].seen;
    CHECK(seen == F_NATTR);
    g_now += 6000;
    CHECK(run_report(&k_admin) == 0); /* nothing left */
}

static void test_subscribe_reaping(void)
{
    /* MRP gives up on a report: reaped. */
    fake_reset(1400);
    subscribe(&k_admin, 100, sub_req(true, 0, 60, false, 1, 0), 1400);
    g_now += 60000;
    mt_im_poll(&g_im);
    CHECK(g_im.subs[0].q.state == Q_REPORT);
    mt_im_on_exchange_failed(&g_im, LAST->exch);
    CHECK(mt_im_sub_count(&g_im) == 0);

    /* Non-success StatusResponse to a report: reaped. */
    subscribe(&k_admin, 101, sub_req(true, 0, 60, false, 1, 0), 1400);
    g_now += 60000;
    mt_im_poll(&g_im);
    ack(&k_admin, LAST->exch, MT_IM_INVALID_SUBSCRIPTION);
    CHECK(mt_im_sub_count(&g_im) == 0);

    /* The report cannot be sent (session gone underneath): reaped. */
    subscribe(&k_admin, 102, sub_req(true, 0, 60, false, 1, 0), 1400);
    g_now += 60000;
    g_send_fail = 1;
    mt_im_poll(&g_im);
    g_send_fail = 0;
    CHECK(mt_im_sub_count(&g_im) == 0);

    /* Session closed / evicted, fabric removed. */
    subscribe(&k_admin, 103, sub_req(true, 0, 60, false, 1, 0), 1400);
    subscribe(&k_viewer, 104, sub_req(true, 0, 60, false, 1, 0), 1400);
    CHECK(mt_im_sub_count(&g_im) == 2);
    mt_im_on_session_closed(&g_im, k_admin.session);
    CHECK(mt_im_sub_count(&g_im) == 1);
    mt_im_on_fabric_removed(&g_im, 2);
    CHECK(mt_im_sub_count(&g_im) == 0);

    /* Priming abandoned (client never acks, exchange fails). */
    rx(&k_admin, 105, MT_IM_OP_SUBSCRIBE, sub_req(true, 0, 60, false, 1, 0));
    CHECK(mt_im_sub_count(&g_im) == 1);
    mt_im_on_exchange_failed(&g_im, 105);
    CHECK(mt_im_sub_count(&g_im) == 0);

    /* keep_subs = false from the same peer on a new session drops its old subscription. */
    subscribe(&k_admin, 106, sub_req(true, 0, 60, false, 1, 0), 1400);
    subscribe(&k_viewer, 107, sub_req(true, 0, 60, false, 1, 0), 1400);
    subscribe(&k_admin2, 108, sub_req(false, 0, 60, false, 1, 0), 1400);
    CHECK(mt_im_sub_count(&g_im) == 2);
    CHECK(g_im.subs[0].q.subj.session == k_admin2.session || g_im.subs[1].q.subj.session == k_admin2.session ||
          g_im.subs[2].q.subj.session == k_admin2.session);

    /* Bad requests. */
    rx(&k_admin, 109, MT_IM_OP_SUBSCRIBE, sub_req(true, 0, 60, false, 0, 0));
    CHECK(status_of(LAST) == MT_IM_INVALID_ACTION);
    rx(&k_admin, 110, MT_IM_OP_SUBSCRIBE, sub_req(true, 0, 60, false, MT_IM_SUB_PATHS + 1, 0));
    CHECK(status_of(LAST) == MT_IM_PATHS_EXHAUSTED);
    /* Interval negotiation: ceiling below floor -> INVALID_ACTION (as chip); above the limit -> 3600. */
    rx(&k_admin, 111, MT_IM_OP_SUBSCRIBE, sub_req(true, 30, 10, false, 1, 0));
    CHECK(status_of(LAST) == MT_IM_INVALID_ACTION);
    subscribe(&k_admin, 112, sub_req(true, 0, 65000, false, 1, 0), 1400);
    CHECK(SAME(LAST->p + 7, 4, 0x25, 0x02, 0x10, 0x0E));
}

static void test_subscribe_capacity(void)
{
    mt_im_subject s = k_admin;
    fake_reset(1400);
    for (int i = 0; i < MT_IM_N_SUBS; i++) {
        s.session = (uint16_t)(10 + i);
        subscribe(&s, (uint16_t)(200 + i), sub_req(true, 0, 600, false, 1, 0), 1400);
    }
    CHECK(mt_im_sub_count(&g_im) == MT_IM_N_SUBS);
    uint32_t first = g_im.subs[0].id;
    /* Apple re-subscribes (keep_subs = true) after a session drop the node never saw: the oldest of
     * that peer gives way. */
    s.session = 40;
    subscribe(&s, 210, sub_req(true, 0, 600, false, 1, 0), 1400);
    CHECK(mt_im_sub_count(&g_im) == MT_IM_N_SUBS);
    bool gone = true;
    for (int i = 0; i < MT_IM_N_SUBS; i++) gone &= g_im.subs[i].id != first;
    CHECK(gone);
    /* Another fabric still gets in: fabric 1 holds more than half. */
    subscribe(&k_viewer, 211, sub_req(true, 0, 600, false, 1, 0), 1400);
    CHECK(mt_im_sub_count(&g_im) == MT_IM_N_SUBS && LAST->op == MT_IM_OP_SUBSCRIBE_RESP);
    for (int i = 0; i < 2; i++) {
        mt_im_subject v = k_viewer;
        v.session = (uint16_t)(50 + i);
        subscribe(&v, (uint16_t)(212 + i), sub_req(true, 0, 600, false, 1, 0), 1400);
    }
    unsigned f2 = 0;
    for (int i = 0; i < MT_IM_N_SUBS; i++) f2 += g_im.subs[i].q.subj.fabric == 2;
    CHECK(f2 == 3);
    /* Three fabrics' worth: a third fabric with fabrics 1 and 2 at exactly half each is refused. */
    mt_im_subject pase = { 60, MT_IM_AUTH_PASE, 0, 0 };
    rx(&pase, 220, MT_IM_OP_SUBSCRIBE, sub_req(true, 0, 600, false, 1, 0));
    CHECK(status_of(LAST) == MT_IM_RESOURCE_EXHAUSTED);
}

static void test_events(void)
{
    static const uint8_t startup[] = { 0x24, 0x00, 0x05 }; /* {0: SoftwareVersion 5} */
    uint64_t no;
    fake_reset(1400);
    CHECK(mt_im_event_emit(&g_im, 0, 0x28, 0, 2, mt_span_of(startup, 3), &no) == MT_OK && no == 0x100);
    /* Read events (wildcard path): the StartUp event, golden EventReportIB. */
    mt_tlv_wr w = req_begin();
    mt_tlv_start(&w, CTX(1), MT_TLV_ARRAY);
    mt_tlv_start(&w, ANON, MT_TLV_LIST);
    mt_tlv_end(&w);
    mt_tlv_end(&w);
    rx(&k_admin, 120, MT_IM_OP_READ, req_end(&w));
    bool ok = SAME(LAST->p, LAST->len, 0x15, 0x36, 0x02,
        0x15, 0x35, 0x01,
          0x37, 0x00, 0x24, 0x01, 0x00, 0x24, 0x02, 0x28, 0x24, 0x03, 0x00, 0x18,
          0x25, 0x01, 0x00, 0x01,       /* EventNumber 0x100 */
          0x24, 0x02, 0x02,             /* Priority CRITICAL */
          0x25, 0x04, 0xE8, 0x03,       /* SystemTimestamp 1000 ms */
          0x35, 0x07, 0x24, 0x00, 0x05, 0x18,
        0x18, 0x18,
        0x18, 0x29, 0x04, 0x24, 0xFF, 0x0B, 0x18);
    CHECK(ok);
    if (!ok) dump(LAST->p, LAST->len);

    /* Subscription with attributes + events, EventMin past the StartUp: no event in priming. */
    subscribe(&k_admin, 121, sub_req(true, 0, 600, true, 1, 0x101), 1400);
    CHECK(g_prime_nev == 0 && LAST->op == MT_IM_OP_SUBSCRIBE_RESP);
    /* A new event wakes it up and is reported once. */
    g_now += 100;
    mt_im_event_emit(&g_im, 0, 0x28, 1, 2, mt_span_of(NULL, 0), &no);
    CHECK(no == 0x101 && g_im.subs[0].dirty);
    CHECK(run_report(&k_admin) == 1 && g_rpt.nev == 1 && g_rpt.ev[0] == 0x101 && g_rpt.n == 0);
    g_now += 100;
    CHECK(run_report(&k_admin) == 0);
    /* Priming without EventMin includes both. */
    subscribe(&k_admin2, 122, sub_req(true, 0, 600, true, 1, 0), 1400);
    CHECK(g_prime_nev == 2);
    CHECK(mt_im_event_emit(&g_im, 0, 0x28, 0, 2, mt_span_of(g_req, MT_IM_EVENT_DATA_MAX + 1), NULL) == MT_ERR_INVALID);
}


/* IM runs on secure sessions only (spec 8.2: every interaction is on a CASE or PASE session). A subject
 * without authentication is dropped before parsing: no report, no write, no subscription, no state. */
static void test_unauthenticated_dropped(void)
{
    static const uint32_t p[][3] = { { 1, 0x201, 0 } };
    const mt_im_subject none = { 70, MT_IM_AUTH_NONE, 0, 0 };
    wreq sp = { 1, 0x201, 0x12, 1900, 0, 0, 0 };
    fake_reset(1200);
    int before = g_nsent;
    uint32_t ver = g_dataver[0];
    rx(&none, 1, MT_IM_OP_READ, read_req(false, 1, p));
    rx(&none, 2, MT_IM_OP_WRITE, write_req(false, false, 1, &sp));
    rx(&none, 3, MT_IM_OP_SUBSCRIBE, sub_req(true, 0, 600, false, 1, 0));
    rx(&none, 4, MT_IM_OP_TIMED, mt_span_of((const uint8_t[]){ 0x15, 0x25, 0x00, 0xE8, 0x03, 0x24, 0xFF, 0x0B, 0x18 }, 9));
    CHECK(g_nsent == before);
    CHECK(g_dataver[0] == ver && mt_im_sub_count(&g_im) == 0 && g_im.xs[0].kind == X_FREE);
}

/* Subscribe intervals (chip ReadHandler::ProcessSubscribeRequest, spec 8.5): MinIntervalFloor above
 * MaxIntervalCeiling is INVALID_ACTION; the chosen MaxInterval lies in [floor, max(3600, ceiling)] and is
 * never below the floor; a zero MaxInterval would make every poll send a liveness report. */
static void test_subscribe_intervals(void)
{
    fake_reset(1200);
    int before = g_nsent;
    rx(&k_admin, 95, MT_IM_OP_SUBSCRIBE, sub_req(true, 30, 10, false, 1, 0));
    CHECK(g_nsent == before + 1 && status_of(LAST) == MT_IM_INVALID_ACTION && mt_im_sub_count(&g_im) == 0);

    fake_reset(1200);
    subscribe(&k_admin, 96, sub_req(true, 4000, 5000, false, 1, 0), 1200);
    CHECK(mt_im_sub_count(&g_im) == 1);
    CHECK(g_im.subs[0].min_s == 4000 && g_im.subs[0].max_s >= 4000 && g_im.subs[0].max_s <= 5000);

    fake_reset(1200);
    subscribe(&k_admin, 97, sub_req(true, 0, 0, false, 1, 0), 1200);
    CHECK(mt_im_sub_count(&g_im) == 1 && g_im.subs[0].max_s >= 1);
    before = g_nsent;
    for (int i = 0; i < 5; i++) {
        mt_im_poll(&g_im);
        if (g_nsent > before && LAST->op == MT_IM_OP_REPORT) ack(&k_admin, LAST->exch, 0);
    }
    CHECK(g_nsent == before); /* clock did not move: no report storm */
}

int main(void)
{
    test_chip_vectors();
    test_read_golden();
    test_read_errors();
    test_wildcard_chunked();
    test_wildcard_flags();
    test_dataversion_filter();
    test_read_busy_and_abort();
    test_write();
    test_write_overflow();
    test_write_list_chunked();
    test_timed();
    test_invoke();
    test_invoke_deferred();
    test_subscribe_priming_liveness();
    test_subscribe_dirty_min_interval();
    test_subscribe_reaping();
    test_subscribe_capacity();
    test_events();
    test_unauthenticated_dropped();
    test_subscribe_intervals();
    printf("matter-im: %d checks, %d failed\n", g_checks, g_fail);
    return g_fail != 0;
}
