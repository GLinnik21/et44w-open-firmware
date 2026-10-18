/* Role checks and NOC -> [ICAC] -> RCAC verification. */
#include <string.h>
#include "mt_cert.h"
#include "cert_internal.h"

mt_err mt_cert_check_noc(const mt_cert *c)
{
    const mt_cert_dn *s = &c->subject;
    if (!c->has_bc || c->is_ca || !c->has_ku || !(c->key_usage & MT_KU_DIGITAL_SIGNATURE)) return MT_ERR_INVALID;
    if ((s->has & (MT_DN_HAS_NODE | MT_DN_HAS_FABRIC)) != (MT_DN_HAS_NODE | MT_DN_HAS_FABRIC)) return MT_ERR_INVALID;
    if (s->node_id == 0 || s->node_id > MT_CERT_NODE_ID_MAX || s->fabric_id == 0) return MT_ERR_INVALID;
    return MT_OK;
}

mt_err mt_cert_check_ca(const mt_cert *c, bool is_root)
{
    uint8_t has = c->subject.has;
    if (!c->has_bc || !c->is_ca || !c->has_ku || !(c->key_usage & MT_KU_KEY_CERT_SIGN)) return MT_ERR_INVALID;
    if (has & (MT_DN_HAS_NODE)) return MT_ERR_INVALID;
    return (has & (is_root ? MT_DN_HAS_RCAC : MT_DN_HAS_ICAC)) ? MT_OK : MT_ERR_INVALID;
}

static mt_err check_time(const mt_cert *c, uint32_t now)
{
    if (!now) return MT_OK; /* time unknown: skip */
    return now < c->not_before || (c->not_after && now > c->not_after) ? MT_ERR_EXPIRED : MT_OK;
}

/* `c` must be signed by `parent` and name it as issuer. */
static mt_err check_link(const mt_cert *c, const mt_cert *parent, mt_buf scratch)
{
    if (!mt_span_eq(c->issuer.raw, parent->subject.raw)) return MT_ERR_INVALID;
    if (c->akid.len && parent->skid.len && !mt_span_eq(c->akid, parent->skid)) return MT_ERR_INVALID;
    return mt_cert_verify_sig(c, parent->pubkey.p, scratch);
}

static mt_err check_fabric(const mt_cert *c, uint64_t fabric_id)
{
    if (!(c->subject.has & MT_DN_HAS_FABRIC)) return MT_OK;
    return c->subject.fabric_id == fabric_id ? MT_OK : MT_ERR_INVALID;
}

mt_err mt_cert_verify_chain(const mt_cert *noc, const mt_cert *icac, const mt_cert *rcac, uint32_t now,
                            mt_buf scratch)
{
    MT_TRY(mt_cert_check_noc(noc));
    MT_TRY(mt_cert_check_ca(rcac, true));
    if (rcac->path_len >= 0 && rcac->path_len < (icac ? 1 : 0)) return MT_ERR_INVALID;
    if (icac) MT_TRY(mt_cert_check_ca(icac, false));
    MT_TRY(check_fabric(rcac, noc->subject.fabric_id));
    if (icac) MT_TRY(check_fabric(icac, noc->subject.fabric_id));
    MT_TRY(check_time(noc, now));
    MT_TRY(check_time(rcac, now));
    if (icac) MT_TRY(check_time(icac, now));

    /* The root signs itself. */
    if (!mt_span_eq(rcac->issuer.raw, rcac->subject.raw)) return MT_ERR_INVALID;
    MT_TRY(check_link(rcac, rcac, scratch));
    if (icac) MT_TRY(check_link(icac, rcac, scratch));
    return check_link(noc, icac ? icac : rcac, scratch);
}
