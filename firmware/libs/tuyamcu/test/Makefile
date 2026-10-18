# Host unit tests: make -C libs/tuyamcu/test
CC     ?= cc
OUT    := build
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -I../include -I../src
SRCS   := $(wildcard ../src/*.c) $(wildcard *.c)

all: $(OUT)/tuyamcu_test
	@$(OUT)/tuyamcu_test

$(OUT)/tuyamcu_test: $(SRCS) $(wildcard *.h) $(wildcard ../include/*.h) $(wildcard ../src/*.h)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
