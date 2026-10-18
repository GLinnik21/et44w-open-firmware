# Host unit tests: make -C libs/tz/test
CC     ?= cc
OUT    := build
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -I../include -I../src -I../../tuyamcu/test
SRCS   := $(wildcard ../src/*.c) $(wildcard *.c)

all: $(OUT)/tz_test
	@$(OUT)/tz_test

$(OUT)/tz_test: $(SRCS) $(wildcard ../include/*.h) $(wildcard ../src/*.h)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
