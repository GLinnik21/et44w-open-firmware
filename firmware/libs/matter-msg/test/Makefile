# Host unit tests: make -C libs/matter-msg/test   (links the shared host mbedtls, build/hosttest.mk)
CC     ?= cc
OUT    := build
.DEFAULT_GOAL := all
include ../../../build/hosttest.mk
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -I../include -I../../matter-core/include -I../../matter-tlv/include -I../../matter-crypto/include $(MBEDTLS_HOST_CFLAGS)
SRCS   := $(wildcard ../src/*.c) $(wildcard ../../matter-tlv/src/*.c) ../../matter-crypto/src/*.c $(wildcard *.c)

all: $(OUT)/msg_test
	@$(OUT)/msg_test

$(OUT)/msg_test: $(SRCS) $(wildcard ../include/*.h) $(wildcard ../../matter-crypto/include/*.h) $(MBEDTLS_HOST_LIB)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -include stdio.h $(SRCS) $(MBEDTLS_HOST_LIB) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
