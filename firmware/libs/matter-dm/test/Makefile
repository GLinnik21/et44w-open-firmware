# Host unit tests: make -C libs/matter-dm/test
CC     ?= cc
OUT    := build
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined \
          -I../include -I../src -I../../matter-im/include -I../../matter-im/src \
          -I../../matter-tlv/include -I../../matter-core/include
SRCS   := $(wildcard ../src/*.c) $(wildcard ../../matter-im/src/*.c) $(wildcard ../../matter-tlv/src/*.c) \
          $(wildcard *.c)
HDRS   := $(wildcard ../include/*.h ../src/*.h ../../matter-im/include/*.h ../../matter-im/src/*.h \
                     ../../matter-tlv/include/*.h ../../matter-core/include/*.h)

all: $(OUT)/dm_test
	@$(OUT)/dm_test

$(OUT)/dm_test: $(SRCS) $(HDRS)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
