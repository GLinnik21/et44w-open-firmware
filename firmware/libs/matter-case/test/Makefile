# Host unit tests: make -C libs/matter-case/test   (links the shared host mbedtls, build/hosttest.mk)
CC     ?= cc
OUT    := build
.DEFAULT_GOAL := all
include ../../../build/hosttest.mk
L      := ../..
INCS   := -I../include -I../src -I$(L)/matter-core/include -I$(L)/matter-tlv/include -I$(L)/matter-msg/include -I$(L)/matter-crypto/include \
          -I$(L)/matter-cert/include -I$(L)/matter-fabric/include -I$(L)/matter-cert/test
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined $(INCS) $(MBEDTLS_HOST_CFLAGS)
SRCS   := $(wildcard ../src/*.c) $(L)/matter-tlv/src/mt_tlv_rd.c $(L)/matter-tlv/src/mt_tlv_wr.c $(L)/matter-msg/src/mt_sc.c \
          $(wildcard $(L)/matter-crypto/src/*.c) $(wildcard $(L)/matter-cert/src/*.c) \
          $(wildcard $(L)/matter-fabric/src/*.c) $(wildcard test_*.c)
HDRS   := $(wildcard ../include/*.h ../src/*.h *.h $(L)/matter-tlv/include/*.h $(L)/matter-msg/include/mt_sc.h $(L)/matter-crypto/include/*.h \
          $(L)/matter-cert/include/*.h $(L)/matter-fabric/include/*.h $(L)/matter-fabric/src/*.h)

all: $(OUT)/case_test
	@$(OUT)/case_test

# Transcript dump for kat.py. To regenerate kat_vectors.h follow the usage line in kat.py (never pipe
# `make dump` straight into kat_vectors.h: make rebuilds from the truncated header).
dump: $(OUT)/case_test
	@$(OUT)/case_test --dump

$(OUT)/case_test: $(SRCS) $(HDRS) $(L)/matter-cert/test/vectors.h $(MBEDTLS_HOST_LIB)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -include stdio.h $(SRCS) $(MBEDTLS_HOST_LIB) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean dump
