/* Test-only CASE initiator (spec 4.14.2) for the node unit test, ported from matter-case/test/test_case.c and
 * driven through mt_test_init's transport (ti). It uses chip's test certificates (matter-cert/test/vectors.h,
 * matter-case/test/keys.h): the device gets Root01 / Node01_02 (no ICAC), the initiator is Node01_01 under
 * ICA01 on the same fabric. Self-consistency only, not interop. */
#ifndef CASE_INI_H
#define CASE_INI_H

#include "mt_fabric.h"
#include "mt_test_init.h"

#define CI_INITIATOR_NODE 0xDEDEDEDE00010001ull   /* Node01_01 */

/* Device-side material for commissioning: RCAC and NOC (TLV), and the operational key of the NOC. */
mt_span ci_root01(void);
mt_span ci_noc_device(void);
void ci_device_key(uint8_t priv[MT_P256_SCALAR_LEN], uint8_t pub[MT_P256_POINT_LEN]);

/* Sigma1..Sigma3 against `target` (the device's fabric as the node holds it: root key, IPK, IDs) over t's
 * unsecured session. MT_OK: t now runs on the CASE session (t->secure). MT_ERR_STATE: the node answered with a
 * StatusReport (t->status_general / status_code); MT_ERR_CRYPTO: Sigma2 did not verify; MT_ERR_TIMEOUT. */
mt_err ci_case(ti *t, const mt_fabric *target);

#endif
