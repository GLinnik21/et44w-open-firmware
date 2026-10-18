/* Internal to matter-fabric. */
#ifndef MT_FABRIC_INTERNAL_H
#define MT_FABRIC_INTERNAL_H

#include "mt_fabric.h"

/* Fill cfid and ipk from root_pub, fabric_id and ipk_epoch. */
mt_err fabric_derive(mt_fabric *f);

/* Stored records (fabric_store.c). All use the caller's scratch except read_priv. */
mt_err fabric_read_priv(const mt_kv_ops *kv, uint8_t index, uint8_t priv[MT_P256_SCALAR_LEN]);
mt_err fabric_load_one(const mt_kv_ops *kv, uint8_t index, mt_fabric *f, mt_buf scratch);
/* Stage the whole image of `f`; certificates come from `src` (pending) or from storage; then finish(). */
mt_err fabric_persist(const mt_kv_ops *kv, const mt_fabric *f, const uint8_t *priv,
                      const uint8_t *certs[3], const uint16_t cert_len[3], mt_buf scratch);
mt_err fabric_erase(const mt_kv_ops *kv, uint8_t index);

#endif
