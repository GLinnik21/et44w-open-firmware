# Host build of mbedtls for the unit tests of pure libs that depend on it (matter-crypto, -cert, ...).
# In libs/<lib>/test/Makefile:
#     .DEFAULT_GOAL := all                        # hosttest.mk defines targets of its own
#     include ../../../build/hosttest.mk
#     CFLAGS += $(MBEDTLS_HOST_CFLAGS)
#     <test binary>: ... $(MBEDTLS_HOST_LIB)        # and add $(MBEDTLS_HOST_LIB) to the link line
# Compiles the same mbedtls sources and config as the firmware (build/hosttest/ shadows only
# the HAVE_ASM switch) once into out-host/mbedtls/, shared by every lib's tests. Objects are written
# via a temp name and renamed, so parallel `make -C libs/*/test` runs can't corrupt the cache.
HT_FW      := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))..)
HT_MBEDTLS := $(HT_FW)/vendor/ameba-rtos-z2/component/common/network/ssl/mbedtls-3.1.0
HT_OUT     ?= $(HT_FW)/out-host/mbedtls
HT_CC      ?= cc

include $(HT_FW)/platform/ambz2/mbedtls_sources.mk
HT_INC := -I$(HT_FW)/build/hosttest -I$(HT_FW)/platform/ambz2/mbedtls -I$(HT_MBEDTLS)/include
HT_CFG := -DMBEDTLS_CONFIG_FILE='"mbedtls_host_config.h"'
HT_OBJ := $(addprefix $(HT_OUT)/,$(MBEDTLS_SRC:.c=.o))
HT_CFGS := $(HT_FW)/build/hosttest/mbedtls_host_config.h $(HT_FW)/build/hosttest/quiet_printf.h $(wildcard $(HT_FW)/platform/ambz2/mbedtls/*.h)

MBEDTLS_HOST_LIB    := $(HT_OUT)/libmbedtls_matter.a
MBEDTLS_HOST_CFLAGS := $(HT_CFG) $(HT_INC)

$(HT_OUT)/%.o: $(HT_MBEDTLS)/library/%.c $(HT_CFGS)
	@mkdir -p $(HT_OUT)
	@$(HT_CC) -std=c11 -O1 -w -include stdio.h -include $(HT_FW)/build/hosttest/quiet_printf.h $(HT_CFG) $(HT_INC) -c $< -o $@.$$$$ && mv $@.$$$$ $@

$(MBEDTLS_HOST_LIB): $(HT_OBJ)
	@rm -f $@.tmp && ar rcs $@.tmp $(HT_OBJ) && mv $@.tmp $@
