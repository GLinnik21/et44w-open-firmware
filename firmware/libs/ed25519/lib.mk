# Ed25519 (RFC 8032, SHA-512) from Monocypher (vendor/Monocypher, CC0 / BSD-2): crypto_ed25519_check for the
# OTA signature. Only the optional Ed25519 file and the core it builds on; unused functions are dropped at link.
MONOCYPHER ?= vendor/Monocypher
LIBS += ed25519
ed25519_INC    := $(MONOCYPHER)/src $(MONOCYPHER)/src/optional
ed25519_SRC    := $(MONOCYPHER)/src/monocypher.c $(MONOCYPHER)/src/optional/monocypher-ed25519.c
ed25519_CFLAGS := -Wno-error
