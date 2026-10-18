# ET-44W floor thermostat: HomeKit Thermostat + Child Lock over the TuyaMCU link.
# Build: make APP=apps/thermostat UNIT=<unit> (from firmware/; `make clean` when switching
# UNIT, make doesn't track it). units/<UNIT>/ holds the unit's name/serial and HomeKit setup info.
UNIT ?= example
$(if $(wildcard $(d)/units/$(UNIT)/unit.h),,$(error no units/$(UNIT)/unit.h))
LIBS += app
app_SRC  := $(addprefix $(d)/,main.c accessory.c thermostat.c thermostat_db.c mcu_link.c thermo_mcu.c clock.c dp_cache.c web.c)
app_INC  := $(d)/units/$(UNIT) $(d) $(OUT)/gen
app_DEPS := sdk hap_pal homekit_adk hap_app wifi_sta netlog ota ota_test wdog tuyamcu tuyamcu_port thermo tz httpd

TM_WEB_DIR := $(d)
include $(d)/web.mk
