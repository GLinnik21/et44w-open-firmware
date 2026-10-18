# Matter firmware, native build with the Arm GNU Toolchain.
#   make UNIT=<unit> OUT=out-matter/<unit>   (APP defaults to apps/thermostat-matter; see its lib.mk)
#   make clean
# Layers (each may use only those below): vendor/ -> platform/<chip> -> libs/* -> the app.
# Vendor trees are read-only; all objects go to $(OUT).

# a recipe that fails (e.g. image packing) must not leave a target that looks up to date
.DELETE_ON_ERROR:

PLATFORM ?= platform/ambz2
APP      ?= apps/thermostat-matter
ifndef TC
TC       := $(shell tools/get-toolchain.sh)
endif
ifeq ($(filter-out clean,$(MAKECMDGOALS))$(if $(MAKECMDGOALS),,all),)
else ifeq ($(wildcard $(TC)/arm-none-eabi-gcc),)
$(error no arm-none-eabi-gcc in TC='$(TC)': tools/get-toolchain.sh failed (see its output above) or TC is wrong)
endif
OUT      ?= out-matter

CROSS    := $(TC)/arm-none-eabi-
CC       := $(CROSS)gcc
OBJCOPY  := $(CROSS)objcopy
SIZE     := $(CROSS)size

CFLAGS     := -std=gnu11 -g -Os -fdata-sections -ffunction-sections -fno-common -MMD -MP
OUR_CFLAGS := -Wall -Wextra -Werror -Wno-unused-parameter -Wno-missing-field-initializers

all: image

include $(PLATFORM)/platform.mk
include build/rules.mk
LIB_DIRS := $(PLATFORM) $(wildcard libs/*) $(APP)
$(foreach d,$(LIB_DIRS),$(eval include $(d)/lib.mk))
$(foreach l,$(LIBS),$(eval $(call lib_rules,$(l))))

$(OUT)/app.axf: $(OBJS) $(LDSCRIPT)
	@echo "  LD   $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-Map=$(OUT)/app.map -o $@ $(OBJS) $(LDLIBS) -T$(LDSCRIPT)
	@$(SIZE) $@

image: $(IMAGE)

clean:
	rm -rf $(OUT)

.PHONY: all image clean
-include $(OBJS:.o=.d)
