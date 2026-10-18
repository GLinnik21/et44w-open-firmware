# Shared basics of the Matter libs (mt_err, byte spans, little-endian helpers). Header-only, pure C11.
# Host test: make -C libs/matter-core/test
ifeq ($(MATTER),1)
LIBS += matter_core
matter_core_INC  := $(d)/include
matter_core_DEFS := -DMATTER=1 # seen by every Matter lib that lists matter_core in its _DEPS
endif
