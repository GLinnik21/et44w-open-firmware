LIBS += app
app_SRC  := $(addprefix $(d)/,main.c accessory.c switch.c mcu_probe.c)
app_INC  := $(d)
app_DEPS := sdk hap_pal homekit_adk hap_app wifi_sta netlog ota ota_test wdog tuyamcu tuyamcu_port $(if $(filter 1,$(BT)),ble_probe)

