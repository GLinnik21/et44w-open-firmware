# HomeKit firmware, native build with the Arm GNU Toolchain.
#   make                          build out/app.axf and the packed flash images
#   make APP=apps/thermostat  build another app
#   make MATTER=1 APP=...           Matter build (implies BT=1), output in out-matter/
#   make clean
# Layers (each may use only those below): vendor/ -> platform/<chip> -> libs/* -> apps/*.
# Vendor trees are read-only; all objects go to out/.

# a recipe that fails (e.g. image packing) must not leave a target that looks up to date
.DELETE_ON_ERROR:

PLATFORM ?= platform/ambz2
APP      ?= apps/example-switch
ifndef TC
TC       := $(shell tools/get-toolchain.sh)
endif
ifeq ($(filter-out clean,$(MAKECMDGOALS))$(if $(MAKECMDGOALS),,all),)
else ifeq ($(wildcard $(TC)/arm-none-eabi-gcc),)
$(error no arm-none-eabi-gcc in TC='$(TC)': tools/get-toolchain.sh failed (see its output above) or TC is wrong)
endif
# MATTER=1 builds the Matter stack: it implies BT=1 and keeps its objects apart in out-matter/ (make
# doesn't track flag changes, so HAP and Matter objects must never share a directory).
ifeq ($(MATTER),1)
override BT := 1
endif
OUT      ?= $(if $(filter 1,$(MATTER)),out-matter,out)

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
