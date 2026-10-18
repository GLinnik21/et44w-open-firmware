/* Internal to matter-tlv: the element-type field (bits 4..0) of a control byte; the tag form is bits 7..5. */
#ifndef MT_TLV_PRIV_H
#define MT_TLV_PRIV_H

enum { T_SINT = 0, T_UINT = 4, T_FALSE = 8, T_TRUE = 9, T_F32 = 10, T_F64 = 11, T_UTF8 = 12,
       T_BYTES = 16, T_NULL = 20, T_STRUCT = 21, T_ARRAY = 22, T_LIST = 23, T_END = 24 };

#endif
