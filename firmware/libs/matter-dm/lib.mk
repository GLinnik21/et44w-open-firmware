# Matter data model: static endpoint/cluster/attribute tables, global attributes, Descriptor cluster,
# data versions, and the mt_im_dm implementation matter-im runs on. Pure C11, no allocation.
# Host test: make -C libs/matter-dm/test
ifeq ($(MATTER),1)
LIBS += matter_dm
matter_dm_INC  := $(d)/include
matter_dm_SRC  := $(wildcard $(d)/src/*.c)
matter_dm_DEPS := matter_core matter_tlv matter_im
endif
