# Matter TLV (spec appendix A): reader, fixed-buffer writer with checkpoint/rollback. Pure C11.
# Host test: make -C libs/matter-tlv/test
LIBS += matter_tlv
matter_tlv_INC  := $(d)/include
matter_tlv_SRC  := $(wildcard $(d)/src/*.c)
matter_tlv_DEPS := matter_core
