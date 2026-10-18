# Host unit tests: make -C libs/matter-im/test
CC     ?= cc
OUT    := build
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined \
          -I../include -I../src -I../../matter-tlv/include -I../../matter-core/include
SRCS   := $(wildcard ../src/*.c) $(wildcard ../../matter-tlv/src/*.c) $(wildcard *.c)
HDRS   := $(wildcard ../include/*.h ../src/*.h *.h ../../matter-tlv/include/*.h ../../matter-core/include/*.h)

all: $(OUT)/im_test
	@$(OUT)/im_test

$(OUT)/im_test: $(SRCS) $(HDRS)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
