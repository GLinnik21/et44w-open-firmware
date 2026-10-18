# Measurement only: BLE stack up with Matter's BTP GATT service, advertising. Built with `make BT=1`.
ifeq ($(BT),1)
LIBS += ble_probe
ble_probe_INC  := $(d)/include
ble_probe_DEFS := -DBLE_PROBE=1
ble_probe_SRC  := $(wildcard $(d)/src/*.c)
ble_probe_DEPS := sdk bt
endif
