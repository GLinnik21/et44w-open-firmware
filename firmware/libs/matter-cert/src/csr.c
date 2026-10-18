/* PKCS#10 CSR for the node's operational key, and the NOCSRElements that wrap it. */
#include <string.h>
#include "mt_cert.h"
#include "mt_tlv.h"
#include "cert_internal.h"
#include "der.h"

#define CSR_MAX 224 /* version, subject O=CSR, SPKI, empty attributes, signature: about 200 bytes */

static const uint8_t VERSION_0[] = { 0x02, 0x01, 0x00 };
static const uint8_t SUBJECT_O_CSR[] = { 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 'C', 'S', 'R' };
static const uint8_t EMPTY_ATTRS[] = { 0xa0, 0x00 };

mt_err mt_cert_build_csr(mt_rng *rng, const uint8_t priv[MT_P256_SCALAR_LEN], const uint8_t pub[MT_CERT_PUBKEY_LEN],
                         mt_buf out, mt_span *csr)
{
    der_w w;
    der_init(&w, out);
    size_t top = der_open(&w, T_SEQ), info = der_open(&w, T_SEQ);
    der_raw(&w, VERSION_0, sizeof VERSION_0);
    der_raw(&w, SUBJECT_O_CSR, sizeof SUBJECT_O_CSR);
    der_raw(&w, MT_DER_SPKI_HEAD, sizeof MT_DER_SPKI_HEAD);
    der_raw(&w, pub, MT_CERT_PUBKEY_LEN);
    der_raw(&w, EMPTY_ATTRS, sizeof EMPTY_ATTRS);
    der_close(&w, info);
    if (w.err) return MT_ERR_BUFFER_TOO_SMALL;

    uint8_t raw[MT_P256_SIG_LEN], der[1 + MT_P256_SIG_DER_MAX];
    mt_err e = mt_crypto_p256_sign(rng, priv, mt_span_of(w.p + info, w.len - info), raw);
    if (e) return e;
    der[0] = 0; /* BIT STRING: no unused bits */
    size_t n = mt_crypto_p256_sig_to_der(raw, der + 1);
    der_raw(&w, MT_DER_SIG_ALG, sizeof MT_DER_SIG_ALG);
    der_put(&w, T_BITS, der, 1 + n);
    der_close(&w, top);
    if (w.err) return MT_ERR_BUFFER_TOO_SMALL;
    *csr = mt_span_of(w.p, w.len);
    return MT_OK;
}

mt_err mt_cert_build_nocsr_elements(mt_rng *rng, const uint8_t priv[MT_P256_SCALAR_LEN],
                                    const uint8_t pub[MT_CERT_PUBKEY_LEN], const uint8_t nonce[MT_CSR_NONCE_LEN],
                                    mt_buf out, mt_span *elements)
{
    uint8_t buf[CSR_MAX];
    mt_span csr;
    mt_err e = mt_cert_build_csr(rng, priv, pub, mt_buf_of(buf, sizeof buf), &csr);
    if (e) return e;
    mt_tlv_wr wr;
    mt_tlv_wr_init(&wr, out);
    if ((e = mt_tlv_start(&wr, mt_tlv_anon(), MT_TLV_STRUCT)) ||
        (e = mt_tlv_put_bytes(&wr, mt_tlv_ctx(1), csr)) ||
        (e = mt_tlv_put_bytes(&wr, mt_tlv_ctx(2), mt_span_of(nonce, MT_CSR_NONCE_LEN))) ||
        (e = mt_tlv_end(&wr)))
        return e;
    return mt_tlv_wr_done(&wr, elements);
}
