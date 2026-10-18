# Host unit tests of the pure parts of the port (store_kv, boot policy, flash guard, mDNS subtypes, rescue and Wi-Fi security policy): make -C libs/matter-port-ambz2/test
CC     ?= cc
OUT    := build
L      := ../..
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined -I../include -I../src \
          -I$(L)/matter-core/include -I$(L)/matter-root/include
SRCS   := ../src/store_kv.c ../src/boot_policy.c ../src/mdns_sub.c $(wildcard test_*.c)
HDRS   := $(wildcard ../include/*.h ../src/*.h $(L)/matter-core/include/*.h $(L)/matter-root/include/mt_netctl.h)

all: $(OUT)/port_test
	@$(OUT)/port_test

$(OUT)/port_test: $(SRCS) $(HDRS)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
