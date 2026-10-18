# Thermostat model: TuyaMCU DP values <-> HomeKit Thermostat/Lock values, with pending-write hold so
# Home doesn't snap back while the MCU catches up. Pure C11, no SDK/OS, no DEPS.
# Host tests: make -C libs/thermo/test
LIBS += thermo
thermo_INC := $(d)/include
thermo_SRC := $(wildcard $(d)/src/*.c)
