# Ed25519 and SHA-512 from Monocypher (vendor/Monocypher, CC0 / BSD-2): crypto_ed25519_check and crypto_sha512_* for
# OTA. Unused functions are dropped at link.
MONOCYPHER ?= vendor/Monocypher
include $(d)/sources.mk
LIBS += ed25519
ed25519_INC    := $(addprefix $(MONOCYPHER)/,$(ED25519_INC))
ed25519_SRC    := $(addprefix $(MONOCYPHER)/,$(ED25519_SRC))
ed25519_CFLAGS := -Wno-error
