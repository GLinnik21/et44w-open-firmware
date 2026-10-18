/* mbedtls config for host tests of the pure Matter libs: the firmware config without the Cortex-M
 * inline assembly in bn_mul.h. */
#pragma once
#include "ambz2_mbedtls_config.h"
#undef MBEDTLS_HAVE_ASM
