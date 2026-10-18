/* Matter operational certificates (RCAC / ICAC / NOC) in Matter-TLV form, and the NOC CSR.
 * Pure C11, no allocation. Decoded certificates keep spans into the caller's TLV, so the TLV buffer
 * must outlive the mt_cert. There is no X.509 parser: to check a signature the TBSCertificate DER is
 * rebuilt from the TLV into a caller scratch buffer (MT_CERT_SCRATCH bytes are enough). */
#ifndef MT_CERT_H
#define MT_CERT_H

#include <stdbool.h>
#include "mt_core.h"
#include "mt_crypto.h"

#define MT_CERT_SCRATCH 640    /* scratch for TBS rebuild; also the largest accepted TLV certificate */
#define MT_CERT_MAX_CATS 3
#define MT_CERT_MAX_EKU 4
#define MT_CERT_MAX_FUTURE_EXT 2
#define MT_CERT_PUBKEY_LEN MT_P256_POINT_LEN
#define MT_CERT_NODE_ID_MAX 0xFFFFFFEFFFFFFFFFull /* above this: group / reserved node ids */

/* Key usage flags as in the Matter TLV (bit 0 = digitalSignature, as in RFC 5280's named bits). */
#define MT_KU_DIGITAL_SIGNATURE 0x01u
#define MT_KU_KEY_CERT_SIGN 0x20u
#define MT_KU_CRL_SIGN 0x40u
/* Extended key usage values as in the Matter TLV. */
#define MT_EKU_SERVER_AUTH 1
#define MT_EKU_CLIENT_AUTH 2

/* Identity attributes of a distinguished name. The raw element list is kept for comparison and for
 * rebuilding the DER name. */
typedef struct {
    mt_span raw;                      /* the DN's TLV elements (no container header) */
    uint64_t node_id, fabric_id, rcac_id, icac_id; /* valid when the matching has_* bit is set */
    uint32_t cats[MT_CERT_MAX_CATS];
    uint8_t n_cats;
    uint8_t has;                      /* MT_DN_HAS_* bits */
} mt_cert_dn;
#define MT_DN_HAS_NODE 0x01
#define MT_DN_HAS_FABRIC 0x02
#define MT_DN_HAS_RCAC 0x04
#define MT_DN_HAS_ICAC 0x08

typedef struct {
    mt_span tlv;                      /* the whole certificate */
    mt_span serial;                   /* 1..20 bytes */
    mt_cert_dn issuer, subject;
    uint32_t not_before, not_after;   /* Matter epoch seconds (since 2000-01-01); not_after 0 = no expiry */
    mt_span pubkey;                   /* 65 bytes, uncompressed P-256 */
    mt_span skid, akid;               /* 20 bytes each when present, else len 0 */
    mt_span future_ext[MT_CERT_MAX_FUTURE_EXT]; /* DER of extra extensions (e.g. SAN), kept verbatim */
    uint8_t n_future_ext;
    mt_span sig;                      /* 64 bytes, raw r||s */
    bool has_bc, is_ca, has_ku;
    int8_t path_len;                  /* -1 = not constrained */
    uint16_t key_usage;
    uint8_t eku[MT_CERT_MAX_EKU], n_eku;
} mt_cert;

/* Parse and structurally validate a Matter-TLV certificate (field order, sizes, algorithms).
 * MT_ERR_INVALID for malformed input, MT_ERR_UNSUPPORTED for another signature / key algorithm. */
mt_err mt_cert_decode(mt_span tlv, mt_cert *out);

/* Rebuild the DER TBSCertificate into scratch; *tbs points into it. */
mt_err mt_cert_build_tbs(const mt_cert *c, mt_buf scratch, mt_span *tbs);
/* Check c's ECDSA-SHA256 signature against the issuer's public key (65 bytes). MT_ERR_CRYPTO on mismatch. */
mt_err mt_cert_verify_sig(const mt_cert *c, const uint8_t issuer_pub[MT_CERT_PUBKEY_LEN], mt_buf scratch);

/* Structural role checks (basic constraints, key usage, identity attributes) for each certificate type. */
mt_err mt_cert_check_noc(const mt_cert *c);
mt_err mt_cert_check_ca(const mt_cert *c, bool is_root);

/* Verify NOC -> [ICAC] -> RCAC: roles, issuer/subject linkage, key identifiers, same fabric ID, path
 * length, every signature, and (when now != 0) every validity period. `now` is Matter epoch seconds;
 * pass 0 when the time is unknown and validity is skipped. A bad signature gives MT_ERR_CRYPTO, an
 * expired or not-yet-valid certificate MT_ERR_EXPIRED (distinct from MT_ERR_INVALID, which covers
 * every structural or linkage problem). icac may be NULL. */
mt_err mt_cert_verify_chain(const mt_cert *noc, const mt_cert *icac, const mt_cert *rcac, uint32_t now,
                            mt_buf scratch);

/* ---- CSR ---- */
/* PKCS#10 CertificationRequest for the P-256 key, subject O=CSR, signed ECDSA-SHA256. */
mt_err mt_cert_build_csr(mt_rng *rng, const uint8_t priv[MT_P256_SCALAR_LEN], const uint8_t pub[MT_CERT_PUBKEY_LEN],
                         mt_buf out, mt_span *csr);
#define MT_CSR_NONCE_LEN 32
/* NOCSRElements TLV { 1: csr, 2: csr_nonce }, ready to be signed by the attestation key. */
mt_err mt_cert_build_nocsr_elements(mt_rng *rng, const uint8_t priv[MT_P256_SCALAR_LEN],
                                    const uint8_t pub[MT_CERT_PUBKEY_LEN], const uint8_t nonce[MT_CSR_NONCE_LEN],
                                    mt_buf out, mt_span *elements);

#endif
