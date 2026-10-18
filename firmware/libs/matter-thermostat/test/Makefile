# Host unit tests: make -C libs/matter-thermostat/test
CC     ?= cc
OUT    := build
INCS   := -I../include -I../src -I../../matter-dm/include -I../../matter-im/include -I../../matter-im/src \
          -I../../matter-tlv/include -I../../matter-core/include -I../../thermo/include
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined $(INCS)
SRCS   := $(wildcard ../src/*.c) $(wildcard ../../matter-dm/src/*.c) $(wildcard ../../matter-im/src/*.c) \
          $(wildcard ../../matter-tlv/src/*.c) $(wildcard ../../thermo/src/thermo.c) $(wildcard *.c)
HDRS   := $(wildcard ../include/*.h ../src/*.h ../../matter-dm/include/*.h ../../matter-dm/src/*.h \
                     ../../matter-im/include/*.h ../../matter-im/src/*.h ../../matter-tlv/include/*.h \
                     ../../matter-core/include/*.h ../../thermo/include/*.h)

all: $(OUT)/thermostat_test
	@$(OUT)/thermostat_test

$(OUT)/thermostat_test: $(SRCS) $(HDRS)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
