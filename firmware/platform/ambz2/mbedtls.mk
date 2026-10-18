# The SDK's mbedtls 3.1.0, built crypto-only with our config (mbedtls/ambz2_mbedtls_config.h; MATTER=1:
# mbedtls/ambz2_mbedtls_matter_config.h).
# Neither the ROM nor the prebuilt SDK libs define mbedtls_* symbols, so nothing clashes.
MBEDTLS := $(SDK)/component/common/network/ssl/mbedtls-3.1.0

LIBS += mbedtls
mbedtls_INC  := $(d)/mbedtls $(MBEDTLS)/include
# MATTER=1 swaps in the Matter config (a superset of the HAP one) and the extra sources it enables.
MBEDTLS_CFG  := $(if $(filter 1,$(MATTER)),ambz2_mbedtls_matter_config.h,ambz2_mbedtls_config.h)
mbedtls_DEFS := -DMBEDTLS_CONFIG_FILE='"$(MBEDTLS_CFG)"'
include $(d)/mbedtls_sources.mk
mbedtls_SRC  := $(addprefix $(MBEDTLS)/library/,$(MBEDTLS_HAP_SRC) $(if $(filter 1,$(MATTER)),$(MBEDTLS_MATTER_SRC)))
# The SDK's ctr_drbg.c has a debug printf() without including <stdio.h>.
mbedtls_CFLAGS := -w $(if $(filter 1,$(MATTER)),-include stdio.h)
