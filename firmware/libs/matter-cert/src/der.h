/* Tiny forward DER emitter used to rebuild the TBSCertificate and the CSR. A constructed element is
 * opened with room for a 3-byte length and compacted when closed, so nothing needs to be sized in
 * advance. Errors are sticky: check der_w.err once at the end. Private to matter-cert. */
#ifndef MT_CERT_DER_H
#define MT_CERT_DER_H

#include <stdbool.h>
#include "mt_core.h"

/* Universal tags used by the TBSCertificate and the CSR. */
enum { T_BOOL = 0x01, T_INT = 0x02, T_BITS = 0x03, T_OCTETS = 0x04, T_OID = 0x06, T_UTF8 = 0x0c,
       T_UTCTIME = 0x17, T_GENTIME = 0x18, T_SEQ = 0x30, T_SET = 0x31, T_PRINTABLE = 0x13, T_IA5 = 0x16 };

typedef struct { uint8_t *p; size_t cap, len; bool err; } der_w;

static inline void der_init(der_w *w, mt_buf b) { w->p = b.p; w->cap = b.cap; w->len = 0; w->err = false; }
size_t der_open(der_w *w, uint8_t tag);              /* returns the marker for der_close */
void der_close(der_w *w, size_t marker);
void der_put(der_w *w, uint8_t tag, const void *v, size_t n);
void der_raw(der_w *w, const void *v, size_t n);     /* pre-encoded DER */
static inline void der_true(der_w *w) { static const uint8_t t = 0xff; der_put(w, T_BOOL, &t, 1); }

#endif
