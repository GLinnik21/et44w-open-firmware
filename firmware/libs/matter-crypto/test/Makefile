# Host unit tests: make -C libs/matter-crypto/test   (links the shared host mbedtls, build/hosttest.mk)
CC     ?= cc
OUT    := build
.DEFAULT_GOAL := all
include ../../../build/hosttest.mk
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -I../include -I../../matter-core/include $(MBEDTLS_HOST_CFLAGS)
SRCS   := $(wildcard ../src/*.c) $(wildcard *.c)

all: $(OUT)/crypto_test
	@$(OUT)/crypto_test

$(OUT)/crypto_test: $(SRCS) $(wildcard ../include/*.h) $(MBEDTLS_HOST_LIB)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -include stdio.h $(SRCS) $(MBEDTLS_HOST_LIB) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
