/* Record layouts (TLV, one kv value each, keys MT_FKEY(index, kind)):
 *   RCAC, ICAC, NOC  the Matter-TLV certificate verbatim (ICAC absent = key absent)
 *   META  struct { 0 version=1, 1 fabricId, 2 nodeId, 3 vendorId, 4 label (utf8), 5 operational private key (32),
 *                  6 IPK epoch key (16), 7 root public key (65) }
 *   ACL   array of ACL entries in the Access Control cluster's shape (mt_acl_entry_encode)
 * The compressed fabric ID and the operational IPK are derived at load, not stored. */
#include <string.h>
#include "fabric_internal.h"

#define META_VERSION 1
#define META_MAX 208     /* worst case is ~190 B */
#define ACL_MAX 432      /* worst case is ~420 B */

static mt_err meta_encode(mt_tlv_wr *w, const mt_fabric *f, const uint8_t priv[MT_P256_SCALAR_LEN])
{
    MT_TRY(mt_tlv_start(w, mt_tlv_anon(), MT_TLV_STRUCT));
    MT_TRY(mt_tlv_put_u(w, mt_tlv_ctx(0), META_VERSION));
    MT_TRY(mt_tlv_put_u(w, mt_tlv_ctx(1), f->fabric_id));
    MT_TRY(mt_tlv_put_u(w, mt_tlv_ctx(2), f->node_id));
    MT_TRY(mt_tlv_put_u(w, mt_tlv_ctx(3), f->vendor_id));
    MT_TRY(mt_tlv_put_utf8(w, mt_tlv_ctx(4), f->label, strlen(f->label)));
    MT_TRY(mt_tlv_put_bytes(w, mt_tlv_ctx(5), mt_span_of(priv, MT_P256_SCALAR_LEN)));
    MT_TRY(mt_tlv_put_bytes(w, mt_tlv_ctx(6), mt_span_of(f->ipk_epoch, MT_IPK_LEN)));
    MT_TRY(mt_tlv_put_bytes(w, mt_tlv_ctx(7), mt_span_of(f->root_pub, MT_P256_POINT_LEN)));
    return mt_tlv_end(w);
}

/* Fills f (identity part) and priv. */
static mt_err meta_decode(mt_span in, mt_fabric *f, uint8_t priv[MT_P256_SCALAR_LEN])
{
    mt_tlv_rd r;
    mt_err e;
    mt_span s;
    unsigned seen = 0;
    mt_tlv_rd_init(&r, in);
    if (mt_tlv_next(&r) || r.type != MT_TLV_STRUCT) return MT_ERR_INVALID;
    MT_TRY(mt_tlv_enter(&r));
    while ((e = mt_tlv_next(&r)) == MT_OK) {
        if (r.tag.kind != MT_TAG_CTX) continue;
        unsigned n = r.tag.num;
        if (n > 7) continue;
        seen |= 1u << n;
        switch (n) {
        case 0: { uint8_t v; MT_TRY(mt_tlv_get_u8(&r, &v)); if (v != META_VERSION) return MT_ERR_INVALID; break; }
        case 1: MT_TRY(mt_tlv_get_u64(&r, &f->fabric_id)); break;
        case 2: MT_TRY(mt_tlv_get_u64(&r, &f->node_id)); break;
        case 3: MT_TRY(mt_tlv_get_u16(&r, &f->vendor_id)); break;
        case 4:
            MT_TRY(mt_tlv_get_utf8(&r, &s));
            if (s.len > MT_FABRIC_LABEL_MAX) return MT_ERR_INVALID;
            memcpy(f->label, s.p, s.len);
            f->label[s.len] = 0;
            break;
        case 5: MT_TRY(mt_tlv_get_bytes_len(&r, MT_P256_SCALAR_LEN, MT_P256_SCALAR_LEN, &s)); memcpy(priv, s.p, s.len); break;
        case 6: MT_TRY(mt_tlv_get_bytes_len(&r, MT_IPK_LEN, MT_IPK_LEN, &s)); memcpy(f->ipk_epoch, s.p, s.len); break;
        case 7: MT_TRY(mt_tlv_get_bytes_len(&r, MT_P256_POINT_LEN, MT_P256_POINT_LEN, &s)); memcpy(f->root_pub, s.p, s.len); break;
        }
    }
    if (e != MT_ERR_NOT_FOUND || seen != 0xFFu) return MT_ERR_INVALID;
    if (!f->fabric_id || f->node_id < 1 || f->node_id > MT_CERT_NODE_ID_MAX || f->root_pub[0] != 0x04) return MT_ERR_INVALID;
    return MT_OK;
}

static mt_err acl_decode(mt_span in, mt_fabric *f)
{
    mt_tlv_rd r;
    mt_err e;
    mt_tlv_rd_init(&r, in);
    f->n_acl = 0;
    if (mt_tlv_next(&r) || r.type != MT_TLV_ARRAY) return MT_ERR_INVALID;
    MT_TRY(mt_tlv_enter(&r));
    while ((e = mt_tlv_next(&r)) == MT_OK) {
        if (f->n_acl == MT_ACL_MAX_ENTRIES) return MT_ERR_BUFFER_TOO_SMALL;
        MT_TRY(mt_acl_entry_decode(&r, &f->acl[f->n_acl]));
        if (!mt_acl_entry_valid(&f->acl[f->n_acl])) return MT_ERR_INVALID;
        f->n_acl++;
    }
    return e == MT_ERR_NOT_FOUND ? MT_OK : MT_ERR_INVALID;
}

static mt_err acl_encode(mt_buf out, const mt_fabric *f, mt_span *enc)
{
    mt_tlv_wr w;
    mt_tlv_wr_init(&w, out);
    MT_TRY(mt_tlv_start(&w, mt_tlv_anon(), MT_TLV_ARRAY));
    for (unsigned i = 0; i < f->n_acl; i++) MT_TRY(mt_acl_entry_encode(&w, mt_tlv_anon(), &f->acl[i]));
    MT_TRY(mt_tlv_end(&w));
    return mt_tlv_wr_done(&w, enc);
}

mt_err fabric_read_priv(const mt_kv_ops *kv, uint8_t index, uint8_t priv[MT_P256_SCALAR_LEN])
{
    uint8_t buf[META_MAX];
    mt_tlv_rd r;
    mt_span key;
    size_t len;
    mt_err e = kv->get(kv->ctx, MT_FKEY(index, MT_FKIND_META), mt_buf_of(buf, sizeof buf), &len);
    if (e == MT_OK) {
        mt_tlv_rd_init(&r, mt_span_of(buf, len));
        if (mt_tlv_next(&r) || mt_tlv_enter(&r) || mt_tlv_find_ctx(&r, 5) ||
            mt_tlv_get_bytes_len(&r, MT_P256_SCALAR_LEN, MT_P256_SCALAR_LEN, &key))
            e = MT_ERR_INVALID;
        else memcpy(priv, key.p, key.len);
    }
    mt_wipe(buf, sizeof buf);
    return e;
}

mt_err fabric_load_one(const mt_kv_ops *kv, uint8_t index, mt_fabric *f, mt_buf scratch)
{
    uint8_t priv[MT_P256_SCALAR_LEN];
    size_t len;
    mt_span enc;
    memset(f, 0, sizeof *f);
    if (scratch.cap < META_MAX) return MT_ERR_BUFFER_TOO_SMALL;
    mt_err e = kv->get(kv->ctx, MT_FKEY(index, MT_FKIND_META), scratch, &len);
    if (e == MT_OK) e = meta_decode(mt_span_of(scratch.p, len), f, priv);
    mt_wipe(priv, sizeof priv);
    mt_wipe(scratch.p, META_MAX);
    if (e) return e;
    if ((e = kv->get(kv->ctx, MT_FKEY(index, MT_FKIND_ACL), scratch, &len)) != MT_OK) return e == MT_ERR_NOT_FOUND ? MT_ERR_INVALID : e;
    enc = mt_span_of(scratch.p, len);
    MT_TRY(acl_decode(enc, f));
    MT_TRY(fabric_derive(f));
    f->index = index;
    return MT_OK;
}

static mt_err put_cert(const mt_kv_ops *kv, uint8_t index, int kind, mt_span c)
{
    return c.len ? kv->set(kv->ctx, MT_FKEY(index, kind), c) : kv->del(kv->ctx, MT_FKEY(index, kind));
}

static mt_err stage(const mt_kv_ops *kv, const mt_fabric *f, const uint8_t *priv, const uint8_t *certs[3],
                    const uint16_t cert_len[3], mt_buf scratch)
{
    mt_tlv_wr w;
    mt_span enc;
    if (scratch.cap < ACL_MAX) return MT_ERR_BUFFER_TOO_SMALL;
    mt_tlv_wr_init(&w, scratch);
    MT_TRY(meta_encode(&w, f, priv));
    MT_TRY(mt_tlv_wr_done(&w, &enc));
    MT_TRY(kv->set(kv->ctx, MT_FKEY(f->index, MT_FKIND_META), enc));
    mt_wipe(scratch.p, enc.len);
    MT_TRY(acl_encode(scratch, f, &enc));
    MT_TRY(kv->set(kv->ctx, MT_FKEY(f->index, MT_FKIND_ACL), enc));
    for (int i = 0; i < 3; i++) {
        int kind = MT_FKIND_RCAC + i;
        if (certs) MT_TRY(put_cert(kv, f->index, kind, mt_span_of(certs[i], cert_len[i])));
        else {   /* unchanged certificates: carry the applied ones over into the new image */
            size_t len;
            mt_err e = kv->get(kv->ctx, MT_FKEY(f->index, kind), scratch, &len);
            if (e == MT_ERR_NOT_FOUND && kind == MT_FKIND_ICAC) len = 0;
            else if (e) return e;
            MT_TRY(put_cert(kv, f->index, kind, mt_span_of(scratch.p, len)));
        }
    }
    return MT_OK;
}

mt_err fabric_persist(const mt_kv_ops *kv, const mt_fabric *f, const uint8_t *priv,
                      const uint8_t *certs[3], const uint16_t cert_len[3], mt_buf scratch)
{
    uint8_t own[MT_P256_SCALAR_LEN];
    mt_err e = MT_OK;
    if (!priv) {
        e = fabric_read_priv(kv, f->index, own);
        priv = own;
    }
    if (!e) e = stage(kv, f, priv, certs, cert_len, scratch);
    mt_wipe(own, sizeof own);
    mt_err fe = kv->finish(kv->ctx, e == MT_OK);
    return e ? e : fe;
}

mt_err fabric_erase(const mt_kv_ops *kv, uint8_t index)
{
    mt_err e = MT_OK;
    for (int kind = MT_FKIND_RCAC; kind <= MT_FKIND_ACL && !e; kind++) e = kv->del(kv->ctx, MT_FKEY(index, kind));
    mt_err fe = kv->finish(kv->ctx, e == MT_OK);
    return e ? e : fe;
}
