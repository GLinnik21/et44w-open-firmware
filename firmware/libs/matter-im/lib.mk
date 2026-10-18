# Matter Interaction Model: codec + server engine (read/report chunking, write, invoke, subscribe,
# timed, events). Data model and exchange layer are injected (include/mt_im.h). Pure C11.
# Host test: make -C libs/matter-im/test
LIBS += matter_im
matter_im_INC  := $(d)/include
matter_im_SRC  := $(wildcard $(d)/src/*.c)
matter_im_DEPS := matter_core matter_tlv
