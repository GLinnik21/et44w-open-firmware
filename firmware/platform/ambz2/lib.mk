# Realtek SDK core (sdk, sdk_sram) and our glue for it.
include $(d)/sdk.mk
include $(d)/mbedtls.mk

LIBS += platform
platform_SRC := $(d)/src/sdk_glue.c $(d)/src/lwip_ula_route.c
platform_DEPS := sdk
platform_CFLAGS := $(if $(filter 1,$(BT)),-DPLATFORM_HAS_BT)

# lwIP's own mDNS responder (dual-stack); replaces the prebuilt lib_mdns, which hardcodes an
# IPv4-only struct netif layout. Options in config/lwipopts.h.
LIBS += lwip_mdns
lwip_mdns_SRC    := $(SDK)/component/common/network/lwip/lwip_v2.0.2/src/apps/mdns/mdns.c
lwip_mdns_DEPS   := sdk
lwip_mdns_CFLAGS := -w

ifeq ($(BT),1)
include $(d)/bt.mk
endif
