/* Matter TLV codec. Pure C11, no allocation: the reader walks a const span, the writer fills a
 * caller buffer. Integers are always decoded to 64 bit and range-checked by the typed getters. */
#ifndef MT_TLV_H
#define MT_TLV_H

#include <stdbool.h>
#include "mt_core.h"

typedef enum { MT_TAG_ANON, MT_TAG_CTX, MT_TAG_COMMON, MT_TAG_IMPLICIT, MT_TAG_FQ } mt_tlv_tagkind;

/* vendor/profile are used by MT_TAG_FQ only; num is the context number (<= 255) or profile tag. */
typedef struct { mt_tlv_tagkind kind; uint16_t vendor, profile; uint32_t num; } mt_tlv_tag;

static inline mt_tlv_tag mt_tlv_anon(void) { mt_tlv_tag t = { MT_TAG_ANON, 0, 0, 0 }; return t; }
static inline mt_tlv_tag mt_tlv_ctx(uint8_t n) { mt_tlv_tag t = { MT_TAG_CTX, 0, 0, n }; return t; }
static inline mt_tlv_tag mt_tlv_common(uint32_t n) { mt_tlv_tag t = { MT_TAG_COMMON, 0, 0, n }; return t; }
static inline mt_tlv_tag mt_tlv_implicit(uint32_t n) { mt_tlv_tag t = { MT_TAG_IMPLICIT, 0, 0, n }; return t; }
static inline mt_tlv_tag mt_tlv_fq(uint16_t vendor, uint16_t profile, uint32_t n) {
    mt_tlv_tag t = { MT_TAG_FQ, vendor, profile, n }; return t;
}
bool mt_tlv_tag_eq(mt_tlv_tag a, mt_tlv_tag b);

typedef enum {
    MT_TLV_NONE = 0, /* no current element */
    MT_TLV_SINT, MT_TLV_UINT, MT_TLV_BOOL, MT_TLV_F32, MT_TLV_F64,
    MT_TLV_UTF8, MT_TLV_BYTES, MT_TLV_NULL,
    MT_TLV_STRUCT, MT_TLV_ARRAY, MT_TLV_LIST
} mt_tlv_type;

/* ---- reader ---- */

typedef struct {
    mt_span in;
    size_t pos;           /* offset of the next element header */
    size_t depth;         /* containers entered */
    mt_tlv_type type;     /* current element (read-only to callers) */
    mt_tlv_tag tag;
    uint64_t val;         /* ints (sign-extended for SINT), bool, float/double bits */
    mt_span str;          /* UTF8/BYTES payload, points into `in` */
} mt_tlv_rd;

void mt_tlv_rd_init(mt_tlv_rd *r, mt_span in);

/* Advance to the next element of the current container. MT_OK; MT_ERR_NOT_FOUND at the end of the
 * container (or of the input at depth 0, sticky); MT_ERR_INVALID if the encoding is malformed.
 * A container that was not entered is skipped whole. */
mt_err mt_tlv_next(mt_tlv_rd *r);
/* Enter the current container; the next mt_tlv_next() yields its first element. */
mt_err mt_tlv_enter(mt_tlv_rd *r);
/* Leave the innermost entered container, skipping whatever is left in it. */
mt_err mt_tlv_exit(mt_tlv_rd *r);
/* Scan the elements after the current position for context tag `n` (stops at the container end).
 * Copy the reader first (`c = *r`) to keep the original position. */
mt_err mt_tlv_find_ctx(mt_tlv_rd *r, uint8_t n);

static inline bool mt_tlv_is_container(const mt_tlv_rd *r) { return r->type >= MT_TLV_STRUCT; }
static inline bool mt_tlv_is_ctx(const mt_tlv_rd *r, uint8_t n) { return r->tag.kind == MT_TAG_CTX && r->tag.num == n; }

/* Typed getters on the current element: MT_ERR_INVALID on a type mismatch or out-of-range value.
 * Signed and unsigned integer elements are interchangeable when the value fits. */
mt_err mt_tlv_get_u64(const mt_tlv_rd *r, uint64_t *out);
mt_err mt_tlv_get_i64(const mt_tlv_rd *r, int64_t *out);
mt_err mt_tlv_get_u32(const mt_tlv_rd *r, uint32_t *out);
mt_err mt_tlv_get_u16(const mt_tlv_rd *r, uint16_t *out);
mt_err mt_tlv_get_u8(const mt_tlv_rd *r, uint8_t *out);
mt_err mt_tlv_get_i32(const mt_tlv_rd *r, int32_t *out);
mt_err mt_tlv_get_i16(const mt_tlv_rd *r, int16_t *out);
mt_err mt_tlv_get_i8(const mt_tlv_rd *r, int8_t *out);
mt_err mt_tlv_get_bool(const mt_tlv_rd *r, bool *out);
mt_err mt_tlv_get_f32(const mt_tlv_rd *r, float *out);   /* single-precision elements only */
mt_err mt_tlv_get_f64(const mt_tlv_rd *r, double *out);  /* double, or single widened */
mt_err mt_tlv_get_utf8(const mt_tlv_rd *r, mt_span *out);
mt_err mt_tlv_get_bytes(const mt_tlv_rd *r, mt_span *out);
/* A byte string of min..max bytes; MT_ERR_INVALID otherwise. */
mt_err mt_tlv_get_bytes_len(const mt_tlv_rd *r, size_t min, size_t max, mt_span *out);

/* Start reading `in` and enter its anonymous outer structure. MT_ERR_INVALID for anything else
 * (including empty input). */
mt_err mt_tlv_open_struct(mt_tlv_rd *r, mt_span in);

/* ---- writer ---- */

typedef struct {
    mt_buf buf;
    size_t len;
    size_t depth;     /* open containers */
    size_t reserve;   /* bytes held back for closing elements: every put leaves them free */
} mt_tlv_wr;

typedef struct { size_t len, depth; } mt_tlv_mark;

void mt_tlv_wr_init(mt_tlv_wr *w, mt_buf buf);
static inline mt_span mt_tlv_wr_span(const mt_tlv_wr *w) { return mt_span_of(w->buf.p, w->len); }
/* MT_ERR_STATE while containers are open, so a half-built message is never sent. */
mt_err mt_tlv_wr_done(const mt_tlv_wr *w, mt_span *out);

/* Checkpoint / rollback: undo everything written (and any opened or closed containers) since
 * the mark. `reserve` is not part of the mark. */
mt_tlv_mark mt_tlv_wr_mark(const mt_tlv_wr *w);
void mt_tlv_wr_rollback(mt_tlv_wr *w, mt_tlv_mark m);

/* Integers use the smallest width that holds the value. Failed puts leave the writer unchanged
 * (MT_ERR_BUFFER_TOO_SMALL; MT_ERR_INVALID for an unencodable argument). */
mt_err mt_tlv_put_u(mt_tlv_wr *w, mt_tlv_tag tag, uint64_t v);
mt_err mt_tlv_put_i(mt_tlv_wr *w, mt_tlv_tag tag, int64_t v);
mt_err mt_tlv_put_bool(mt_tlv_wr *w, mt_tlv_tag tag, bool v);
mt_err mt_tlv_put_null(mt_tlv_wr *w, mt_tlv_tag tag);
mt_err mt_tlv_put_f32(mt_tlv_wr *w, mt_tlv_tag tag, float v);
mt_err mt_tlv_put_f64(mt_tlv_wr *w, mt_tlv_tag tag, double v);
mt_err mt_tlv_put_utf8(mt_tlv_wr *w, mt_tlv_tag tag, const char *s, size_t len);
mt_err mt_tlv_put_bytes(mt_tlv_wr *w, mt_tlv_tag tag, mt_span b);
/* Append already-encoded TLV (e.g. a stored certificate) verbatim. */
mt_err mt_tlv_put_raw(mt_tlv_wr *w, mt_span enc);
/* `type` is MT_TLV_STRUCT, MT_TLV_ARRAY or MT_TLV_LIST. */
mt_err mt_tlv_start(mt_tlv_wr *w, mt_tlv_tag tag, mt_tlv_type type);
mt_err mt_tlv_end(mt_tlv_wr *w); /* may use the reserved bytes */

#endif
