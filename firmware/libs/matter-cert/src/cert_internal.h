/* Constants shared inside matter-cert. */
#ifndef MT_CERT_INTERNAL_H
#define MT_CERT_INTERNAL_H

#include <stdint.h>

#define MT_CERT_SERIAL_MAX 20
#define MT_CERT_KID_LEN 20

/* DN attribute numbers used as TLV context tags (bit 7 set = PrintableString for 1..15). */
#define MT_DN_ATTR_DOMAIN_COMPONENT 16
#define MT_DN_ATTR_NODE_ID 17
#define MT_DN_ATTR_FWSIGN_ID 18
#define MT_DN_ATTR_ICAC_ID 19
#define MT_DN_ATTR_RCAC_ID 20
#define MT_DN_ATTR_FABRIC_ID 21
#define MT_DN_ATTR_NOC_CAT 22
#define MT_DN_PRINTABLE 0x80


/* Fixed DER fragments shared by the TBSCertificate and the CSR. */
static const uint8_t MT_DER_SIG_ALG[] = { 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
/* SubjectPublicKeyInfo up to and including the BIT STRING's unused-bits byte; the 65-byte point follows. */
static const uint8_t MT_DER_SPKI_HEAD[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00 };

#endif
