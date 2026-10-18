/* mbedtls config for host tests of the pure Matter libs: the Matter config without the Cortex-M
 * inline assembly in bn_mul.h. */
#pragma once
#include "ambz2_mbedtls_matter_config.h"
#undef MBEDTLS_HAVE_ASM
