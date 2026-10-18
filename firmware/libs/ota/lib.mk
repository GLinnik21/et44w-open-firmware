# OTA: signed upload into the idle slot, trial boot, rollback. See include/ota.h.
# homekit_adk only for HAP_ed25519_verify (PAL/HAPCrypto.h); mbedtls for streaming SHA-512.
LIBS += ota
ota_INC  := $(d)/include
ota_SRC  := $(wildcard $(d)/src/*.c)
ota_DEPS := sdk mbedtls homekit_adk net_listen
