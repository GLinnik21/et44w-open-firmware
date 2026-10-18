/* Flash map for C code, generated at compile time from ../partitions.def (the single source of truth).
 * Gives FLASH_<name>_OFFSET and FLASH_<name>_SIZE, e.g. FLASH_kv_OFFSET. */
#pragma once

#define FLASH_TOTAL(size) enum { FLASH_TOTAL_SIZE = size };
#define FLASH_PART(name, offset, size, owner) enum { FLASH_##name##_OFFSET = offset, FLASH_##name##_SIZE = size };
#include "../partitions.def"
#undef FLASH_TOTAL
#undef FLASH_PART

/* DCT modules that fit in kv: each takes 4 KiB, doubled for its backup copy. */
#define FLASH_KV_DCT_MODULES (FLASH_kv_SIZE / (2 * 0x1000))
