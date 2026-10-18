# Host unit tests: make -C libs/matter-core/test
# Also proves the shared host mbedtls build (build/hosttest.mk) with a SHA-256 known answer.
CC     ?= cc
OUT    := build
.DEFAULT_GOAL := all
include ../../../build/hosttest.mk
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -I../include $(MBEDTLS_HOST_CFLAGS)
SRCS   := $(wildcard *.c)

all: $(OUT)/core_test
	@$(OUT)/core_test

$(OUT)/core_test: $(SRCS) $(wildcard ../include/*.h) $(MBEDTLS_HOST_LIB)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) $(MBEDTLS_HOST_LIB) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
