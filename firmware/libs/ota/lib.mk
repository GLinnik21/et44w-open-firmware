# OTA: signed upload into the idle slot, trial boot, rollback. See include/ota.h.
# ed25519 for the signature (Monocypher); mbedtls for streaming SHA-512.
LIBS += ota
ota_INC  := $(d)/include
ota_SRC  := $(wildcard $(d)/src/*.c)
ota_DEPS := sdk mbedtls ed25519 net_listen
