# Link test for libs/matter-port-ambz2 (make MATTER=1 APP=apps/matter-port-link): the matter-base boot wiring with
# the port and a bare node (endpoint 0 only, public connectedhomeip TEST attestation, a freshly generated setup
# code). Never pushed to a device; its size against apps/matter-cryptolink is the port's cost.
ifneq ($(MATTER),1)
$(error apps/matter-port-link needs MATTER=1)
endif
LIBS += app
app_SRC  := $(d)/main.c tools/matter-host/test_credentials.c
app_INC  := $(d) $(OUT)/gen-$(notdir $(d)) apps/example-switch tools/matter-host
app_DEPS := sdk netlog ota wdog matter_port_ambz2 matter_core matter_tlv matter_crypto matter_cert matter_msg matter_btp \
            matter_xchg matter_pase matter_case matter_fabric matter_im matter_dm matter_root matter_node mbedtls

# Setup code + SPAKE2+ verifier, generated per build directory (secret-ish: it holds the passcode; out-matter/
# is git-ignored). Printed QR / manual code: $(OUT)/gen-matter-port-link/setup.txt
PL_SETUP := $(OUT)/gen-$(notdir $(d))/matter_setup_info.h
$(PL_SETUP): tools/matter_setup.py
	@mkdir -p $(dir $@)
	@umask 077 && $(PYTHON) tools/matter_setup.py $@ --rendezvous onnetwork > $(dir $@)setup.txt
$(call obj,$(d)/main.c): $(PL_SETUP)
