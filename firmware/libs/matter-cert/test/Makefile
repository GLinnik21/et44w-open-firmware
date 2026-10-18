# Host unit tests: make -C libs/matter-cert/test   (links the shared host mbedtls, build/hosttest.mk)
CC     ?= cc
OUT    := build
.DEFAULT_GOAL := all
include ../../../build/hosttest.mk
INCS   := -I../include -I../../matter-core/include -I../../matter-tlv/include -I../../matter-crypto/include
# _POSIX_C_SOURCE: popen for the openssl CSR check (glibc hides it under -std=c11; stdio.h is force-included first)
CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined $(INCS) $(MBEDTLS_HOST_CFLAGS)
SRCS   := $(wildcard ../src/*.c) ../../matter-tlv/src/mt_tlv_rd.c ../../matter-tlv/src/mt_tlv_wr.c \
          ../../matter-crypto/src/*.c $(wildcard test_*.c)
HDRS   := $(wildcard ../include/*.h ../src/*.h ../../matter-tlv/include/*.h ../../matter-crypto/include/*.h)

all: $(OUT)/cert_test
	@$(OUT)/cert_test

$(OUT)/cert_test: $(SRCS) $(HDRS) vectors.h $(MBEDTLS_HOST_LIB)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -include stdio.h $(SRCS) $(MBEDTLS_HOST_LIB) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
