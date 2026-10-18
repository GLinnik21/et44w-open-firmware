/* Shared basics of the Matter libs: error type, byte spans and little-endian helpers. Header-only,
 * pure C11, no allocation. Every mt_* lib returns mt_err and takes caller-owned buffers. */
#ifndef MT_CORE_H
#define MT_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef enum {
    MT_OK = 0,
    MT_ERR_INVALID,          /* malformed input or bad argument */
    MT_ERR_BUFFER_TOO_SMALL, /* caller's output buffer or a fixed table is full */
    MT_ERR_NOT_FOUND,
    MT_ERR_CRYPTO,           /* crypto primitive failed or a signature/tag did not verify */
    MT_ERR_UNSUPPORTED,      /* valid but not implemented by this minimal stack */
    MT_ERR_STATE,            /* call not allowed in the current state */
    MT_ERR_TIMEOUT,
    MT_ERR_IO,               /* port (storage, socket, radio) failed */
    MT_ERR_EXPIRED,          /* certificate outside its validity period (not yet valid or past notAfter) */
    MT_ERR_DUPLICATE,        /* message counter already seen: drop the payload, but still acknowledge it */
    MT_ERR_STALE             /* message counter older than the replay window: drop, nothing to acknowledge */
} mt_err;

/* Return early with x's error. */
#define MT_TRY(x) do { mt_err e_ = (x); if (e_ != MT_OK) return e_; } while (0)

/* Read-only bytes and a writable buffer. Neither owns its memory. */
typedef struct { const uint8_t *p; size_t len; } mt_span;
typedef struct { uint8_t *p; size_t cap; } mt_buf;

static inline mt_span mt_span_of(const void *p, size_t len) { mt_span s = { (const uint8_t *)p, len }; return s; }
static inline mt_buf mt_buf_of(void *p, size_t cap) { mt_buf b = { (uint8_t *)p, cap }; return b; }
static inline bool mt_span_eq(mt_span a, mt_span b) { return a.len == b.len && (a.len == 0 || !memcmp(a.p, b.p, a.len)); }

/* Little-endian accessors; Matter's wire format is little-endian throughout. */
static inline uint16_t mt_get_le16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1] << 8); }
static inline uint32_t mt_get_le32(const uint8_t *p) { return (uint32_t)mt_get_le16(p) | (uint32_t)mt_get_le16(p + 2) << 16; }
static inline uint64_t mt_get_le64(const uint8_t *p) { return (uint64_t)mt_get_le32(p) | (uint64_t)mt_get_le32(p + 4) << 32; }

static inline void mt_put_le16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void mt_put_le32(uint8_t *p, uint32_t v) { mt_put_le16(p, (uint16_t)v); mt_put_le16(p + 2, (uint16_t)(v >> 16)); }
static inline void mt_put_le64(uint8_t *p, uint64_t v) { mt_put_le32(p, (uint32_t)v); mt_put_le32(p + 4, (uint32_t)(v >> 32)); }

/* Zero memory that held secrets; volatile so the stores are not optimised away. */
static inline void mt_wipe(void *p, size_t n) { volatile uint8_t *v = (volatile uint8_t *)p; while (n--) *v++ = 0; }
/* Compare secrets (MICs, confirmation values, IDs derived from keys) in time independent of their contents. */
static inline bool mt_ct_eq(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    uint8_t d = 0;
    while (n--) d |= (uint8_t)(*x++ ^ *y++);
    return d == 0;
}

/* Wrap-safe millisecond timers: has deadline t been reached, and how long until it is (0 once due). */
static inline bool mt_due(uint32_t now, uint32_t t) { return (int32_t)(now - t) >= 0; }
static inline uint32_t mt_until(uint32_t now, uint32_t t) { return mt_due(now, t) ? 0 : t - now; }
static inline uint32_t mt_min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }

/* Key/value storage port shared by every persisting lib (matter-fabric, matter-root, node). Keys are 16-bit:
 * fabric index << 8 | record kind, index 0 = node-level records (see MT_FKEY in mt_fabric.h). */
typedef struct mt_kv_ops {
    void *ctx;
    /* Read the applied value into out; *len = its size. MT_ERR_NOT_FOUND if absent,
     * MT_ERR_BUFFER_TOO_SMALL if it does not fit. */
    mt_err (*get)(void *ctx, uint16_t key, mt_buf out, size_t *len);
    /* Stage a value / a deletion (deleting an absent key is MT_OK). MT_ERR_IO on failure. */
    mt_err (*set)(void *ctx, uint16_t key, mt_span val);
    mt_err (*del)(void *ctx, uint16_t key);
    /* Make everything staged since the last finish() durable atomically (apply) or drop it. */
    mt_err (*finish)(void *ctx, bool apply);
} mt_kv_ops;

#endif
