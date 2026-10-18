# Matter node: wires matter-xchg to PASE/CASE and the Interaction Model, owns the commissioning window, the
# fail-safe side effects, the mDNS record set and endpoint 0. Pure C11, ports injected.
# Host test: make -C libs/matter-node/test   Host tool: make -C tools/matter-host test
ifeq ($(MATTER),1)
LIBS += matter_node
matter_node_INC  := $(d)/include
matter_node_SRC  := $(wildcard $(d)/src/*.c)
matter_node_DEPS := matter_core matter_tlv matter_crypto matter_cert matter_msg matter_xchg matter_btp matter_pase \
                    matter_case matter_fabric matter_im matter_dm matter_root mbedtls
endif
