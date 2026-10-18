/* Rebuild the DER TBSCertificate from a decoded Matter-TLV certificate (Matter spec 6.5.x mapping). */
#include <string.h>
#include "mt_cert.h"
#include "mt_tlv.h"
#include "cert_internal.h"
#include "der.h"

static const uint8_t VERSION_3[] = { 0xa0, 0x03, 0x02, 0x01, 0x02 };
static const uint8_t OID_STD_PREFIX[] = { 0x55, 0x04 };
static const uint8_t OID_EKU_PREFIX[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03 };
static const uint8_t OID_MATTER_PREFIX[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x01 };
static const uint8_t OID_DC[] = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19 };
/* Last OID byte of 2.5.4.x for DN attributes 1..15 (CN, SN, serialNumber, C, L, ST, O, OU, title, name,
 * givenName, initials, generationQualifier, dnQualifier, pseudonym). */
static const uint8_t ATTR_OID[] = { 0, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c, 0x29, 0x2a, 0x2b, 0x2c, 0x2e, 0x41 };

static void put_hex(der_w *w, uint64_t v, unsigned digits)
{
    uint8_t s[16];
    for (unsigned i = 0; i < digits; i++)
        s[i] = (uint8_t)"0123456789ABCDEF"[(v >> (4 * (digits - 1 - i))) & 0xf];
    der_put(w, T_UTF8, s, digits);
}

static void put_oid(der_w *w, const uint8_t *prefix, size_t plen, uint8_t last)
{
    uint8_t oid[12];
    memcpy(oid, prefix, plen);
    oid[plen] = last;
    der_put(w, T_OID, oid, plen + 1);
}

static void put_attr_value(der_w *w, mt_tlv_rd *r, unsigned attr)
{
    if (attr >= MT_DN_ATTR_NODE_ID) {
        put_hex(w, r->val, attr == MT_DN_ATTR_NOC_CAT ? 8 : 16);
    } else {
        uint8_t t = attr == MT_DN_ATTR_DOMAIN_COMPONENT ? T_IA5 : (r->tag.num & MT_DN_PRINTABLE) ? T_PRINTABLE : T_UTF8;
        der_put(w, t, r->str.p, r->str.len);
    }
}

/* Name ::= SEQUENCE OF { SET OF { SEQUENCE { OID, value } } }, one RDN per attribute, in TLV order. */
static mt_err put_name(der_w *w, mt_span raw)
{
    mt_tlv_rd r;
    mt_tlv_rd_init(&r, raw);
    size_t name = der_open(w, T_SEQ);
    mt_err e;
    while (!(e = mt_tlv_next(&r))) {
        unsigned attr = r.tag.num & 0x7f;
        size_t set = der_open(w, T_SET), seq = der_open(w, T_SEQ);
        if (attr == MT_DN_ATTR_DOMAIN_COMPONENT) der_put(w, T_OID, OID_DC, sizeof OID_DC);
        else if (attr > MT_DN_ATTR_DOMAIN_COMPONENT) put_oid(w, OID_MATTER_PREFIX, sizeof OID_MATTER_PREFIX, (uint8_t)(attr - 16));
        else put_oid(w, OID_STD_PREFIX, sizeof OID_STD_PREFIX, ATTR_OID[attr]);
        put_attr_value(w, &r, attr);
        der_close(w, seq);
        der_close(w, set);
    }
    der_close(w, name);
    return e == MT_ERR_NOT_FOUND ? MT_OK : e;
}

static void put2(char *s, unsigned v) { s[0] = (char)('0' + v / 10 % 10); s[1] = (char)('0' + v % 10); }

/* Matter epoch seconds -> UTCTime (before 2050) or GeneralizedTime. */
static void put_time(der_w *w, uint32_t t)
{
    uint32_t days = t / 86400, secs = t % 86400;
    uint32_t z = days + 10957 + 719468;           /* days since 0000-03-01 (Hinnant's civil_from_days) */
    uint32_t era = z / 146097, doe = z % 146097;
    uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100), mp = (5 * doy + 2) / 153;
    uint32_t d = doy - (153 * mp + 2) / 5 + 1, m = mp < 10 ? mp + 3 : mp - 9;
    uint32_t y = yoe + era * 400 + (m <= 2);
    char s[16], *q = s;
    if (y >= 2050) { put2(q, y / 100); q += 2; }
    put2(q, y); put2(q + 2, m); put2(q + 4, d);
    put2(q + 6, secs / 3600); put2(q + 8, secs / 60 % 60); put2(q + 10, secs % 60);
    q += 12;
    *q++ = 'Z';
    der_put(w, y >= 2050 ? T_GENTIME : T_UTCTIME, s, (size_t)(q - s));
}

/* ---- extensions: SEQUENCE { OID 2.5.29.id, [critical TRUE], OCTET STRING { value } } ---- */

typedef struct { size_t seq, oct; } ext_m;

static ext_m ext_open(der_w *w, uint8_t id, bool critical)
{
    ext_m m;
    m.seq = der_open(w, T_SEQ);
    put_oid(w, (const uint8_t[]){ 0x55, 0x1d }, 2, id);
    if (critical) der_true(w);
    m.oct = der_open(w, T_OCTETS);
    return m;
}

static void ext_close(der_w *w, ext_m m)
{
    der_close(w, m.oct);
    der_close(w, m.seq);
}

static void put_basic_constraints(der_w *w, const mt_cert *c)
{
    ext_m m = ext_open(w, 0x13, true);
    size_t s = der_open(w, T_SEQ);
    if (c->is_ca) der_true(w);
    if (c->path_len >= 0) der_put(w, T_INT, &c->path_len, 1);
    der_close(w, s);
    ext_close(w, m);
}

static uint8_t rev8(uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 8; i++, b >>= 1) r = (uint8_t)(r << 1 | (b & 1));
    return r;
}

/* Matter keeps the named bits as a mask with bit 0 = digitalSignature; DER lists them MSB first. */
static void put_key_usage(der_w *w, uint16_t ku)
{
    uint8_t bits[3] = { 0, rev8((uint8_t)ku), (uint8_t)((ku >> 8) & 1 ? 0x80 : 0) };
    size_t n = bits[2] ? 2 : 1;                       /* content bytes */
    uint8_t last = bits[n], unused = 0;
    while (last && !(last & 1)) { last >>= 1; unused++; }
    bits[0] = unused;
    ext_m m = ext_open(w, 0x0f, true);
    der_put(w, T_BITS, bits, n + 1);
    ext_close(w, m);
}

static void put_eku(der_w *w, const mt_cert *c)
{
    ext_m m = ext_open(w, 0x25, true);
    size_t s = der_open(w, T_SEQ);
    for (unsigned i = 0; i < c->n_eku; i++) put_oid(w, OID_EKU_PREFIX, sizeof OID_EKU_PREFIX, c->eku[i]);
    der_close(w, s);
    ext_close(w, m);
}

static void put_extensions(der_w *w, const mt_cert *c)
{
    size_t tag = der_open(w, 0xa3), seq = der_open(w, T_SEQ);
    if (c->has_bc) put_basic_constraints(w, c);
    if (c->has_ku) put_key_usage(w, c->key_usage);
    if (c->n_eku) put_eku(w, c);
    if (c->skid.len) {
        ext_m m = ext_open(w, 0x0e, false);
        der_put(w, T_OCTETS, c->skid.p, c->skid.len);
        ext_close(w, m);
    }
    if (c->akid.len) {
        ext_m m = ext_open(w, 0x23, false);
        size_t s = der_open(w, T_SEQ);
        der_put(w, 0x80, c->akid.p, c->akid.len);
        der_close(w, s);
        ext_close(w, m);
    }
    for (unsigned i = 0; i < c->n_future_ext; i++) der_raw(w, c->future_ext[i].p, c->future_ext[i].len);
    der_close(w, seq);
    der_close(w, tag);
}

mt_err mt_cert_build_tbs(const mt_cert *c, mt_buf scratch, mt_span *tbs)
{
    der_w w;
    der_init(&w, scratch);
    size_t top = der_open(&w, T_SEQ);
    der_raw(&w, VERSION_3, sizeof VERSION_3);
    uint8_t serial[MT_CERT_SERIAL_MAX + 1], pad = c->serial.p[0] >> 7;   /* keep the INTEGER positive */
    serial[0] = 0;
    memcpy(serial + 1, c->serial.p, c->serial.len);
    der_put(&w, T_INT, serial + 1 - pad, c->serial.len + pad);
    der_raw(&w, MT_DER_SIG_ALG, sizeof MT_DER_SIG_ALG);
    mt_err e = put_name(&w, c->issuer.raw);
    size_t validity = der_open(&w, T_SEQ);
    put_time(&w, c->not_before);
    if (c->not_after) put_time(&w, c->not_after);
    else der_put(&w, T_GENTIME, "99991231235959Z", 15);   /* notAfter 0 = no well-defined expiry */
    der_close(&w, validity);
    if (!e) e = put_name(&w, c->subject.raw);
    der_raw(&w, MT_DER_SPKI_HEAD, sizeof MT_DER_SPKI_HEAD);
    der_raw(&w, c->pubkey.p, c->pubkey.len);
    if (c->has_bc || c->has_ku || c->n_eku || c->skid.len || c->akid.len || c->n_future_ext)
        put_extensions(&w, c);
    der_close(&w, top);
    if (e) return e;
    if (w.err) return MT_ERR_BUFFER_TOO_SMALL;
    *tbs = mt_span_of(w.p, w.len);
    return MT_OK;
}

mt_err mt_cert_verify_sig(const mt_cert *c, const uint8_t issuer_pub[MT_CERT_PUBKEY_LEN], mt_buf scratch)
{
    mt_span tbs;
    mt_err e = mt_cert_build_tbs(c, scratch, &tbs);
    return e ? e : mt_crypto_p256_verify(issuer_pub, tbs, c->sig.p);
}
