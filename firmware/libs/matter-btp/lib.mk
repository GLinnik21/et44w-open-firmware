# Matter BTP engine (Matter spec 4.19): handshake, segmentation, acks. Pure C11, transport-neutral.
# Host test: make -C libs/matter-btp/test
LIBS += matter_btp
matter_btp_SRC  := $(wildcard $(d)/src/*.c)
matter_btp_INC  := $(d)/include
matter_btp_DEPS := matter_core
