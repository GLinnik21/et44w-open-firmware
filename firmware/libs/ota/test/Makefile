# Host unit tests: make -C libs/ota/test   (links the shared host mbedtls, build/hosttest.mk)
# ota_key, and ota_receive with the firmware's Ed25519 (vendored ADK) on fake flash/sockets, against headers made
# by tools/ota_push.py (vectors.h, regenerate with gen_vectors.py).
CC     ?= cc
OUT    := build
.DEFAULT_GOAL := all
include ../../../build/hosttest.mk
ED25519 := ../../../vendor/HomeKitADK/PAL/Crypto/MbedTLS/Ed25519
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -Ishim -I../src -I../../tuyamcu/test $(MBEDTLS_HOST_CFLAGS)
SRCS   := ../src/ota_key.c ../src/ota_receive.c fake.c test_ota_key.c test_ota_receive.c

all: $(OUT)/ota_test
	@$(OUT)/ota_test

# The vendored Ed25519 builds with warnings off, as in the firmware.
$(OUT)/ed25519_host.o: ed25519_host.c shim/HAPCrypto.h
	@mkdir -p $(OUT)
	$(CC) -std=c11 -O1 -w -Ishim -I$(ED25519) $(MBEDTLS_HOST_CFLAGS) -c $< -o $@

$(OUT)/ota_test: $(SRCS) $(OUT)/ed25519_host.o $(wildcard *.h shim/*.h shim/*/*.h ../src/*.h) $(MBEDTLS_HOST_LIB)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) $(OUT)/ed25519_host.o $(MBEDTLS_HOST_LIB) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
