#include <string.h>
#include "fabric_internal.h"

mt_err mt_fabric_compress_id(const uint8_t root_pub[MT_P256_POINT_LEN], uint64_t fabric_id, uint8_t out[MT_CFID_LEN])
{
    uint8_t salt[8];
    if (root_pub[0] != 0x04) return MT_ERR_INVALID;
    for (int i = 0; i < 8; i++) salt[i] = (uint8_t)(fabric_id >> (56 - 8 * i));
    return mt_crypto_hkdf_sha256(mt_span_of(salt, 8), mt_span_of(root_pub + 1, MT_P256_POINT_LEN - 1),
                                 mt_span_of("CompressedFabric", 16), mt_buf_of(out, MT_CFID_LEN));
}

mt_err mt_fabric_derive_ipk(const uint8_t epoch[MT_IPK_LEN], const uint8_t cfid[MT_CFID_LEN], uint8_t out[MT_IPK_LEN])
{
    return mt_crypto_hkdf_sha256(mt_span_of(cfid, MT_CFID_LEN), mt_span_of(epoch, MT_IPK_LEN),
                                 mt_span_of("GroupKey v1.0", 13), mt_buf_of(out, MT_IPK_LEN));
}

mt_err fabric_derive(mt_fabric *f)
{
    MT_TRY(mt_fabric_compress_id(f->root_pub, f->fabric_id, f->cfid));
    return mt_fabric_derive_ipk(f->ipk_epoch, f->cfid, f->ipk);
}

mt_err mt_fabric_destination_id(const uint8_t ipk[MT_IPK_LEN], const uint8_t random[MT_CASE_RANDOM_LEN],
                                const uint8_t root_pub[MT_P256_POINT_LEN], uint64_t fabric_id, uint64_t node_id,
                                uint8_t out[MT_DEST_ID_LEN])
{
    uint8_t msg[MT_CASE_RANDOM_LEN + MT_P256_POINT_LEN + 16];
    memcpy(msg, random, MT_CASE_RANDOM_LEN);
    memcpy(msg + MT_CASE_RANDOM_LEN, root_pub, MT_P256_POINT_LEN);
    mt_put_le64(msg + MT_CASE_RANDOM_LEN + MT_P256_POINT_LEN, fabric_id);
    mt_put_le64(msg + MT_CASE_RANDOM_LEN + MT_P256_POINT_LEN + 8, node_id);
    return mt_crypto_hmac_sha256(mt_span_of(ipk, MT_IPK_LEN), mt_span_of(msg, sizeof msg), out);
}

mt_err mt_fabric_match_destination(const mt_fabric_table *t, const uint8_t random[MT_CASE_RANDOM_LEN],
                                   const uint8_t dest_id[MT_DEST_ID_LEN], const mt_fabric **out)
{
    const mt_fabric *f;
    for (unsigned n = 0; (f = mt_fabric_nth(t, n)) != NULL; n++) {
        uint8_t id[MT_DEST_ID_LEN];
        MT_TRY(mt_fabric_destination_id(f->ipk, random, f->root_pub, f->fabric_id, f->node_id, id));
        if (mt_ct_eq(id, dest_id, sizeof id)) { *out = f; return MT_OK; }
    }
    return MT_ERR_NOT_FOUND;
}
