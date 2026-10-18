# HomeKit ADK platform abstraction layer (PAL) for Realtek AmebaZ2 (RTL8710C/RTL8720C):
# FreeRTOS + lwIP + Realtek DCT/mDNS. One source file per PAL module.
LIBS += hap_pal
hap_pal_INC  := $(d)/include
hap_pal_SRC  := $(wildcard $(d)/src/*.c)
hap_pal_DEPS := homekit_adk sdk mbedtls
