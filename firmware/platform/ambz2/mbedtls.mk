# The SDK's mbedtls 3.1.0, built crypto-only with our config (mbedtls/ambz2_mbedtls_config.h).
# Neither the ROM nor the prebuilt SDK libs define mbedtls_* symbols, so nothing clashes.
MBEDTLS := $(SDK)/component/common/network/ssl/mbedtls-3.1.0

LIBS += mbedtls
mbedtls_INC  := $(d)/mbedtls $(MBEDTLS)/include
mbedtls_DEFS := -DMBEDTLS_CONFIG_FILE='"ambz2_mbedtls_config.h"'
include $(d)/mbedtls_sources.mk
mbedtls_SRC  := $(addprefix $(MBEDTLS)/library/,$(MBEDTLS_SRC))
# The SDK's ctr_drbg.c has a debug printf() without including <stdio.h>.
mbedtls_CFLAGS := -w -include stdio.h
