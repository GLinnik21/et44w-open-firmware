/* The DNS-SD record set (spec 4.3): what the port advertises. The node only describes the records; the port
 * owns the responder and re-reads the set when ports.mdns_changed fires.
 *  - Commissionable (4.3.1), while a window is open: _matterc._udp, instance = the window's random 64-bit name
 *    (16 upper-case hex digits); subtypes _L<long discriminator>, _S<upper 4 bits>, _V<vendor id>, _CM (4.3.1.3);
 *    TXT D, CM (1 = the device's own passcode, 2 = an enhanced window, 4.3.1.5), VP (VID+PID), DT, DN, SII, SAI,
 *    T=0 (no TCP), PH (4.3.1.11-4.3.1.13; 4.3.4 for the MRP keys).
 *  - Operational (4.3.2), per fabric (committed, or pending under the fail-safe): _matter._tcp, instance =
 *    <compressed fabric ID>-<node ID> as 16 upper-case hex digits each; subtype _I<compressed fabric ID>;
 *    TXT SII, SAI, T=0. */
#include <stdarg.h>
#include <stdio.h>

#include "node_priv.h"

static void hex16(char *out, const uint8_t *b, size_t n)
{
    static const char k[] = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = k[b[i] >> 4];
        out[2 * i + 1] = k[b[i] & 15];
    }
    out[2 * n] = 0;
}

static void hex_u64(char *out, uint64_t v)
{
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (56 - 8 * i));
    hex16(out, b, sizeof b);
}

/* "key=<printf>", truncated to the slot. */
static void add_txt(mt_node_mdns_rec *r, const char *key, const char *fmt, ...)
{
    char *t;
    int k;
    va_list ap;
    if (r->n_txt >= MT_NODE_MDNS_TXT_MAX) return;
    t = r->txt[r->n_txt++];
    k = snprintf(t, sizeof r->txt[0], "%s=", key);
    if (k < 0 || (size_t)k >= sizeof r->txt[0]) return;
    va_start(ap, fmt);
    vsnprintf(t + k, sizeof r->txt[0] - (size_t)k, fmt, ap);
    va_end(ap);
}

static void add_sub(mt_node_mdns_rec *r, const char *fmt, ...)
{
    va_list ap;
    if (r->n_sub >= MT_NODE_MDNS_SUB_MAX) return;
    va_start(ap, fmt);
    vsnprintf(r->sub[r->n_sub++], sizeof r->sub[0], fmt, ap);
    va_end(ap);
}

static void add_mrp(const mt_node *n, mt_node_mdns_rec *r)
{
    add_txt(r, "SII", "%lu", (unsigned long)n->mrp_idle_ms);
    add_txt(r, "SAI", "%lu", (unsigned long)n->mrp_active_ms);
    add_txt(r, "T", "0");
}

static void commissionable(const mt_node *n, mt_node_mdns_rec *r)
{
    const mt_basic_cfg *b = n->basic_cfg;
    r->operational = false;
    hex16(r->instance, n->win.instance, sizeof n->win.instance);
    add_sub(r, "_L%u", (unsigned)n->win.discriminator);
    add_sub(r, "_S%u", (unsigned)(n->win.discriminator >> 8));
    add_sub(r, "_V%u", (unsigned)b->vendor_id);
    add_sub(r, "_CM");
    add_txt(r, "D", "%u", (unsigned)n->win.discriminator);
    add_txt(r, "CM", "%u", n->win.kind == MT_WINDOW_ENHANCED ? 2u : 1u);
    add_txt(r, "VP", "%u+%u", (unsigned)b->vendor_id, (unsigned)b->product_id);
    if (n->device_type) add_txt(r, "DT", "%lu", (unsigned long)n->device_type);
    if (n->device_name && n->device_name[0]) add_txt(r, "DN", "%.32s", n->device_name); /* <= 32 bytes (4.3.1.10) */
    add_mrp(n, r);
    if (n->pairing_hint) add_txt(r, "PH", "%u", (unsigned)n->pairing_hint);
}

static void operational(const mt_node *n, const mt_fabric *f, mt_node_mdns_rec *r)
{
    char cfid[17];
    r->operational = true;
    hex16(cfid, f->cfid, MT_CFID_LEN);
    memcpy(r->instance, cfid, 16);
    r->instance[16] = '-';
    hex_u64(r->instance + 17, f->node_id);
    add_sub(r, "_I%s", cfid);
    add_mrp(n, r);
}

unsigned mt_node_mdns_count(const mt_node *n)
{
    return (mt_node_window_open(n) ? 1u : 0u) + mt_fabric_count(&n->fabrics);
}

bool mt_node_mdns_get(const mt_node *n, unsigned idx, mt_node_mdns_rec *out)
{
    const mt_fabric *f;
    memset(out, 0, sizeof *out);
    if (mt_node_window_open(n)) {
        if (idx == 0) { commissionable(n, out); return true; }
        idx--;
    }
    f = mt_fabric_nth(&n->fabrics, idx);
    if (!f) return false;
    operational(n, f, out);
    return true;
}
