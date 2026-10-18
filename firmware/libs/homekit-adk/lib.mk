# Apple HomeKit ADK core (HAP over IP) with its mbedtls crypto backend. Platform-independent: the
# platform's PAL (e.g. libs/hap-pal-ambz2) provides the HAPPlatform* functions it calls.
ADK ?= vendor/HomeKitADK
# 0 none, 1 +errors/faults/log, 2 +info, 3 +debug
HAP_LOG_LEVEL ?= 2

LIBS += homekit_adk
homekit_adk_INC  := $(ADK)/HAP $(ADK)/PAL $(ADK)/External/Base64 $(ADK)/External/HTTP $(ADK)/External/JSON
homekit_adk_DEFS := -DHAP_LOG_LEVEL=$(HAP_LOG_LEVEL)
homekit_adk_SRC  := $(wildcard $(ADK)/HAP/*.c) $(wildcard $(ADK)/PAL/*.c) $(wildcard $(ADK)/External/*/*.c) \
                    $(ADK)/PAL/Crypto/MbedTLS/HAPMbedTLS.c
homekit_adk_DEPS := mbedtls
homekit_adk_CFLAGS := -include $(d)/mbedtls2_compat.h -Wno-error

