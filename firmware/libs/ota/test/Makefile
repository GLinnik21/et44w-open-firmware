# Host unit tests: make -C libs/ota/test   (links the shared host mbedtls, build/hosttest.mk)
# ota_key, Ed25519 (Monocypher, as in the firmware) and ota_receive on fake flash/sockets, against headers made
# by tools/ota_push.py (vectors.h, regenerate with gen_vectors.py).
CC     ?= cc
OUT    := build
.DEFAULT_GOAL := all
include ../../../build/hosttest.mk
MONO   := ../../../vendor/Monocypher/src
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -Ishim -I../include -I../src -I../../tuyamcu/test -I$(MONO) -I$(MONO)/optional \
          $(MBEDTLS_HOST_CFLAGS)
SRCS   := ../src/ota_key.c ../src/ota_receive.c fake.c test_ota_key.c test_ota_receive.c test_ed25519.c

all: $(OUT)/ota_test
	@$(OUT)/ota_test

# Monocypher builds with warnings off, as in the firmware (libs/ed25519).
$(OUT)/monocypher.o: $(MONO)/monocypher.c $(MONO)/optional/monocypher-ed25519.c
	@mkdir -p $(OUT)
	$(CC) -std=c11 -O1 -w -I$(MONO) -I$(MONO)/optional -c $(MONO)/monocypher.c -o $@
	$(CC) -std=c11 -O1 -w -I$(MONO) -I$(MONO)/optional -c $(MONO)/optional/monocypher-ed25519.c -o $(OUT)/monocypher-ed25519.o

$(OUT)/ota_test: $(SRCS) $(OUT)/monocypher.o $(wildcard *.h shim/*.h shim/*/*.h ../src/*.h) $(MBEDTLS_HOST_LIB)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) $(OUT)/monocypher.o $(OUT)/monocypher-ed25519.o $(MBEDTLS_HOST_LIB) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
