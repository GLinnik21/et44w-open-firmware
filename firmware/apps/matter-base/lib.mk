# Measurement only: the example-switch wiring without HAP, plus the BLE probe (make APP=apps/matter-base BT=1).
# make ... NET_PROBE=1 adds the IoT -> Home reachability probe; that build never confirms (with or without BT=1).
# Its size is the base a Matter firmware would start from.
LIBS += app
app_SRC  := $(d)/main.c $(d)/selfcheck.c apps/example-switch/mcu_probe.c
app_INC  := $(d) apps/example-switch
app_DEPS := sdk wifi_sta netlog ota wdog tuyamcu tuyamcu_port $(if $(filter 1,$(BT)),ble_probe)
ifeq ($(NET_PROBE),1)
app_SRC  += $(d)/net_probe.c
app_DEFS := -DNET_PROBE
endif
