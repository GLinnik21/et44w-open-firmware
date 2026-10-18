/* Host test shim: lwIP's millisecond clock (fake.c). */
#pragma once
#include <stdint.h>
typedef uint32_t u32_t;
u32_t sys_now(void);
