# Host unit tests: make -C libs/matter-node/test   (links the shared host mbedtls, build/hosttest.mk)
CC     ?= cc
OUT    := build
.DEFAULT_GOAL := all
include ../../../build/hosttest.mk
L      := ../..
LIBS_  := matter-core matter-tlv matter-crypto matter-cert matter-fabric matter-msg matter-xchg matter-btp matter-pase matter-case matter-im matter-dm matter-root
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined -I../include -I$(L)/matter-root/test -I$(L)/matter-case/test -I$(L)/matter-cert/test \
          $(foreach l,$(LIBS_),-I$(L)/$(l)/include) $(MBEDTLS_HOST_CFLAGS)
SRCS   := $(wildcard ../src/*.c) $(foreach l,$(filter-out matter-core,$(LIBS_)),$(wildcard $(L)/$(l)/src/*.c)) \
          $(wildcard *.c)
HDRS   := $(wildcard ../include/*.h ../src/*.h *.h *.inc) $(foreach l,$(LIBS_),$(wildcard $(L)/$(l)/include/*.h))

all: $(OUT)/node_test
	@$(OUT)/node_test

$(OUT)/node_test: $(SRCS) $(HDRS) $(MBEDTLS_HOST_LIB)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -include stdio.h $(SRCS) $(MBEDTLS_HOST_LIB) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
