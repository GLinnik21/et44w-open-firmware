# Wi-Fi station with DHCP and reconnect. See include/wifi_sta.h.
LIBS += wifi_sta
wifi_sta_INC  := $(d)/include
wifi_sta_SRC  := $(wildcard $(d)/src/*.c)
wifi_sta_DEPS := sdk
# Matter builds: credentials set at runtime (wifi_sta_set_credentials); HAP builds compile exactly as before.
ifeq ($(MATTER),1)
wifi_sta_DEFS := -DWIFI_STA_RUNTIME=1
endif
