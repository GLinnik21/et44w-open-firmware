# Thin facade over mbedtls for the Matter stack: SHA-256, HMAC, HKDF, AES-CCM, CTR-DRBG, P-256 ECDH / ECDSA
# and the point / scalar primitives SPAKE2+ needs. Pure C11 on top of mbedtls (no SDK/OS).
# Host test: make -C libs/matter-crypto/test
ifeq ($(MATTER),1)
LIBS += matter_crypto
matter_crypto_INC  := $(d)/include
matter_crypto_SRC  := $(wildcard $(d)/src/*.c)
matter_crypto_DEPS := matter_core mbedtls
endif
