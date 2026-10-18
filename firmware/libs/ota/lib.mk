# OTA: signed upload into the idle slot, trial boot, rollback. See include/ota.h.
# Monocypher (libs/ed25519) for the Ed25519 signature and the streaming SHA-512 of the image.
LIBS += ota
ota_INC  := $(d)/include
ota_SRC  := $(wildcard $(d)/src/*.c)
ota_DEPS := sdk ed25519 net_listen
