# Host unit tests: make -C libs/matter-fabric/test   (links the shared host mbedtls, build/hosttest.mk)
CC     ?= cc
OUT    := build
.DEFAULT_GOAL := all
include ../../../build/hosttest.mk
L      := ../..
INCS   := -I../include -I$(L)/matter-core/include -I$(L)/matter-tlv/include -I$(L)/matter-crypto/include \
          -I$(L)/matter-cert/include -I$(L)/matter-cert/test
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined $(INCS) $(MBEDTLS_HOST_CFLAGS)
SRCS   := $(wildcard ../src/*.c) $(L)/matter-tlv/src/mt_tlv_rd.c $(L)/matter-tlv/src/mt_tlv_wr.c \
          $(L)/matter-crypto/src/*.c $(L)/matter-cert/src/*.c $(wildcard test_*.c)
HDRS   := $(wildcard ../include/*.h ../src/*.h $(L)/matter-tlv/include/*.h $(L)/matter-crypto/include/*.h $(L)/matter-cert/include/*.h)

all: $(OUT)/fabric_test
	@$(OUT)/fabric_test

$(OUT)/fabric_test: $(SRCS) $(HDRS) $(L)/matter-cert/test/vectors.h $(MBEDTLS_HOST_LIB)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -include stdio.h $(SRCS) $(MBEDTLS_HOST_LIB) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
