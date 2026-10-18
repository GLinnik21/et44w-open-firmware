# Wi-Fi station with DHCP and reconnect. See include/wifi_sta.h.
LIBS += wifi_sta
wifi_sta_INC  := $(d)/include
wifi_sta_SRC  := $(wildcard $(d)/src/*.c)
wifi_sta_DEPS := sdk
