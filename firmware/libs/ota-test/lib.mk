# Bench-only OTA failure modes for rollback tests: `make OTA_TEST=never_confirm|fault` (see include/ota_test.h).
# A normal build compiles to an empty ota_test_start() and ota_test_confirm_hook == ota_confirm.
# Run `make clean` when changing OTA_TEST; make doesn't track flags.
OTA_TEST ?=
ifneq ($(filter-out never_confirm fault,$(OTA_TEST)),)
$(error OTA_TEST must be never_confirm or fault)
endif
LIBS += ota_test
ota_test_INC  := $(d)/include
ota_test_SRC  := $(wildcard $(d)/src/*.c)
ota_test_DEFS := $(if $(OTA_TEST),-DOTA_TEST_$(OTA_TEST))
ota_test_DEPS := sdk ota
