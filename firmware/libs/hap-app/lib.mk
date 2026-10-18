# HomeKit accessory core shared by apps: HAP task (platform objects, server, run loop) and the
# accessory information, protocol information and pairing services. See include/hap_app.h.
LIBS += hap_app
hap_app_INC  := $(d)/include
hap_app_SRC  := $(wildcard $(d)/src/*.c)
hap_app_DEPS := sdk hap_pal homekit_adk
