/* App credentials -> mt_node_credentials. The DAC private key never leaves the port: the node gets a signer that
 * uses it with its own DRBG (seeded from the SDK entropy source). */
#include <string.h>

#include "port.h"

static const mtp_credentials *cred;
static mt_rng sign_rng;
static bool sign_rng_ready;

static mt_err dac_sign(void *ctx, mt_span msg, uint8_t sig[MT_P256_SIG_LEN])
{
    (void)ctx;
    if (!sign_rng_ready) {
        if (mt_rng_init(&sign_rng, mtp_entropy, NULL) != MT_OK) return MT_ERR_CRYPTO;
        sign_rng_ready = true;
    }
    return mt_crypto_p256_sign(&sign_rng, cred->dac_priv, msg, sig);
}

mt_err mtp_creds_build(const mtp_credentials *in, mt_node_credentials *out)
{
    if (!in || !in->dac_priv || !in->w0 || !in->l || !in->dac.len || !in->pai.len || !in->cd.len)
        return MT_ERR_INVALID;
    cred = in;
    memset(out, 0, sizeof *out);
    memcpy(out->w0, in->w0, sizeof out->w0);
    memcpy(out->l, in->l, sizeof out->l);
    out->salt = in->salt;
    out->iterations = in->iterations;
    out->discriminator = in->discriminator;
    out->attest.dac = in->dac;
    out->attest.pai = in->pai;
    out->attest.cd = in->cd;
    out->attest.vendor_id = in->vendor_id;
    out->attest.product_id = in->product_id;
    out->attest.ctx = NULL;
    out->attest.sign = dac_sign;
    return MT_OK;
}
