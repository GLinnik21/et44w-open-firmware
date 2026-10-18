# Host unit tests: make -C libs/matter-tlv/test
CC     ?= cc
OUT    := build
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined -I../include -I../../matter-core/include
SRCS   := $(wildcard ../src/*.c) $(wildcard *.c)

all: $(OUT)/tlv_test
	@$(OUT)/tlv_test

$(OUT)/tlv_test: $(SRCS) $(wildcard ../include/*.h) $(wildcard ../../matter-core/include/*.h)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
