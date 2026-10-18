# Matter endpoint 1: Thermostat (HEAT) + Identify, mapped onto libs/thermo. Pure C11 on top of matter-dm.
# Host test: make -C libs/matter-thermostat/test
ifeq ($(MATTER),1)
LIBS += matter_thermostat
matter_thermostat_INC  := $(d)/include
matter_thermostat_SRC  := $(wildcard $(d)/src/*.c)
matter_thermostat_DEPS := matter_core matter_tlv matter_im matter_dm thermo
endif
