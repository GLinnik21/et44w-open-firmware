# Host unit tests: make -C libs/matter-root/test   (links the shared host mbedtls, build/hosttest.mk)
CC     ?= cc
OUT    := build
.DEFAULT_GOAL := all
include ../../../build/hosttest.mk
L      := ../..
INCS   := -I../include -I$(L)/matter-core/include -I$(L)/matter-tlv/include -I$(L)/matter-im/include \
          -I$(L)/matter-im/src -I$(L)/matter-dm/include -I$(L)/matter-fabric/include -I$(L)/matter-cert/include \
          -I$(L)/matter-crypto/include -I$(L)/matter-cert/test -I$(L)/matter-case/test
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined $(INCS) $(MBEDTLS_HOST_CFLAGS)
SRCS   := $(wildcard ../src/*.c) $(wildcard $(L)/matter-dm/src/*.c) $(wildcard $(L)/matter-im/src/*.c) \
          $(wildcard $(L)/matter-tlv/src/*.c) $(wildcard $(L)/matter-fabric/src/*.c) $(wildcard $(L)/matter-cert/src/*.c) \
          $(wildcard $(L)/matter-crypto/src/*.c) $(wildcard *.c)
HDRS   := $(wildcard *.inc ../include/*.h ../src/*.h *.h $(L)/matter-*/include/*.h) $(L)/matter-cert/test/vectors.h \
          $(L)/matter-case/test/keys.h

all: $(OUT)/root_test
	@$(OUT)/root_test

$(OUT)/root_test: $(SRCS) $(HDRS) $(MBEDTLS_HOST_LIB)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -include stdio.h $(SRCS) $(MBEDTLS_HOST_LIB) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
