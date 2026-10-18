# Host unit tests: make -C libs/thermo/test
CC     ?= cc
OUT    := build
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -I../include -I../src -I../../tuyamcu/test -I../../tuyamcu/include
SRCS   := $(wildcard ../src/*.c) $(wildcard *.c) ../../tuyamcu/src/tm_allow.c # cross-check of the DP allowlist

all: $(OUT)/thermo_test
	@$(OUT)/thermo_test

$(OUT)/thermo_test: $(SRCS) $(wildcard ../include/*.h) $(wildcard ../src/*.h)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
