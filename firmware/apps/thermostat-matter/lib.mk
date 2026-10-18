# ET-44W floor thermostat as a Matter 1.3 device (on-network commissioning, BLE for the
# first 15 min while uncommissioned).
#   make MATTER=1 APP=apps/thermostat-matter UNIT=<unit>      (from firmware/; `make clean` when
#   switching UNIT, make doesn't track it)
# Per unit (git-ignored): units/<UNIT>/matter_unit.h = Matter setup (verifier, discriminator, serial; no passcode).
# Create it once, never regenerate it for a commissioned unit (the QR code changes):
#   make MATTER=1 APP=apps/thermostat-matter UNIT=<unit> SERIAL=<serial> SETUP_TXT=<file> matter-unit
# SETUP_TXT receives the passcode, QR payload and manual code (keep it outside the repo, e.g. secrets/).
# Per unit, tracked: units/<UNIT>/unit.h (THERMOSTAT_NAME, THERMOSTAT_SERIAL). Also needs wifi_credentials.h and
# ota_pubkey.h (see the .example files; ota_pubkey.h must hold the real key or the image can never be updated over
# the air).
ifneq ($(MATTER),1)
$(error apps/thermostat-matter needs MATTER=1)
endif
UNIT ?= example
TM_UNIT_H  := $(d)/units/$(UNIT)/matter_unit.h

ifeq ($(filter matter-unit,$(MAKECMDGOALS)),)
$(if $(wildcard $(TM_UNIT_H)),,$(error no $(TM_UNIT_H): create it with the matter-unit target (see lib.mk)))
$(if $(wildcard $(d)/units/$(UNIT)/unit.h),,$(error no $(d)/units/$(UNIT)/unit.h))
# The all-zero placeholder is a small-order key: libs/ota refuses every upload with it (forged signatures would
# verify), so such an image could only be replaced over UART.
$(if $(shell grep -E '0x[0-9a-fA-F]*[1-9a-fA-F]' $(d)/ota_pubkey.h 2>/dev/null),,$(error $(d)/ota_pubkey.h missing or all-zero))
# The development network is the only one an uncommissioned unit knows: the .example placeholder would leave it
# offline (no OTA, no netlog; a trial then rolls back after 5 min). Copy the real IoT credentials.
$(if $(shell grep -q '"my-network"' $(d)/wifi_credentials.h 2>/dev/null && echo x),$(error $(d)/wifi_credentials.h holds the .example placeholder network))
endif

LIBS += app
# make BLE_WINDOW_S=<s>: shorter BLE window for debug builds (matter_config.h)
app_CFLAGS := $(if $(BLE_WINDOW_S),-DBLE_WINDOW_S=$(BLE_WINDOW_S))
app_SRC  := $(addprefix $(d)/,main.c thermo_link.c health.c clock.c thermo_mcu.c web.c dp_cache.c) \
            tools/matter-host/test_credentials.c
app_INC  := $(d) $(d)/units/$(UNIT) tools/matter-host \
            $(OUT)/gen
app_DEPS := sdk wifi_sta netlog ota ota_test wdog tuyamcu tuyamcu_port thermo tz httpd matter_port_ambz2 \
            matter_thermostat matter_core matter_tlv matter_crypto matter_cert matter_msg matter_xchg matter_btp matter_pase \
            matter_case matter_fabric matter_im matter_dm matter_root matter_node btp_port_ambz2 mbedtls

# The web page (web/index.html) compiled in as a byte array: $(OUT)/gen/web_page.h, for web.c.
$(OUT)/gen/web_page.h: $(d)/web/index.html tools/embed_c.py
	@mkdir -p $(dir $@)
	python3 tools/embed_c.py $< $@ WebPage
$(call obj,$(d)/web.c): $(OUT)/gen/web_page.h

.PHONY: matter-unit
matter-unit:
	@test -n "$(SERIAL)" -a -n "$(SETUP_TXT)" || { echo "usage: make ... UNIT=<unit> SERIAL=<serial> SETUP_TXT=<file> matter-unit"; exit 1; }
	@test ! -e "$(TM_UNIT_H)" || { echo "$(TM_UNIT_H) exists: a unit keeps its setup code"; exit 1; }
	@test ! -e "$(SETUP_TXT)" || { echo "$(SETUP_TXT) exists: refusing to overwrite"; exit 1; }
	@mkdir -p $(dir $(TM_UNIT_H))
	@umask 077 && $(PYTHON) tools/matter_setup.py $(TM_UNIT_H) --unit $(SERIAL) --rendezvous ble > $(SETUP_TXT)
	@echo "wrote $(TM_UNIT_H); setup code in $(SETUP_TXT)"
