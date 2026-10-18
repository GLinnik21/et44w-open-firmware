/* matter-thermostat internals shared by the two cluster files. */
#ifndef MT_TS_PRIV_H
#define MT_TS_PRIV_H

#include "mt_thermostat.h"

/* Integer value of the element `v` is positioned on. INVALID_DATA_TYPE for a non-integer element,
 * CONSTRAINT_ERROR for null (every attribute here is non-nullable for writes) or a value beyond 64 bit. */
static inline mt_im_status ts_get_int(const mt_tlv_rd *v, int64_t *out)
{
    if (v->type == MT_TLV_NULL) return MT_IM_CONSTRAINT_ERROR;
    if (v->type != MT_TLV_SINT && v->type != MT_TLV_UINT) return MT_IM_INVALID_DATA_TYPE;
    return mt_tlv_get_i64(v, out) ? MT_IM_CONSTRAINT_ERROR : MT_IM_SUCCESS;
}

static inline uint32_t ts_now(const mt_thermostat *t)
{
    return t->cfg.now_ms ? t->cfg.now_ms(t->cfg.ctx) : 0;
}

/* Integer command field `tag` of the CommandFields struct `f`. INVALID_COMMAND if it is absent or not an integer,
 * CONSTRAINT_ERROR for a value beyond 64 bit. */
static inline mt_im_status ts_int_field(const mt_tlv_rd *f, uint8_t tag, int64_t *out)
{
    mt_tlv_rd x;
    if (mt_im_field(f, tag, &x) || (x.type != MT_TLV_UINT && x.type != MT_TLV_SINT)) return MT_IM_INVALID_COMMAND;
    return mt_tlv_get_i64(&x, out) ? MT_IM_CONSTRAINT_ERROR : MT_IM_SUCCESS;
}

/* The Matter-visible view of the model. */
void ts_view(const mt_thermostat *t, mt_thermostat_snap *s);

/* identify.c */
void ts_identify_fill(mt_dm_cluster *c, void *ctx);
/* Counts IdentifyTime down; marks it dirty per step. Returns ms to the next step, UINT32_MAX when idle. */
uint32_t ts_identify_tick(mt_thermostat *t, mt_dm *dm, uint32_t now);

/* schedule.c */
void ts_onoff_fill(mt_dm_cluster *c, void *ctx);

/* thermostat.c */
void ts_thermostat_fill(mt_dm_cluster *c, mt_thermostat *t);

#endif
