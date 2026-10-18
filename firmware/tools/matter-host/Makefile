# matter-host: the Matter node stack on the Mac. Output: ../../out-host/matter-host/ (git-ignored).
#   make            build matter-host (node) and matter-host-client (loopback client)
#   make run        run the node on UDP [::]:5540 (kv in $(OUT)/kv, dns-sd records)
#   make test       kv store test, then start the node on a free port, run the loopback client against it, kill the node
#   make e2e        the matter.js scenario (e2e.sh): commission, read, subscribe, write, restart, second fabric, remove
# PYTHON runs tools/matter_setup.py (stdlib only, Python 3.8+) to make the QR code, manual code and verifier.
CC     ?= cc
PYTHON ?= python3
FW     := ../..
OUT    := $(FW)/out-host/matter-host
.DEFAULT_GOAL := all
include $(FW)/build/hosttest.mk

L        := $(FW)/libs
NODE_LIBS := matter-tlv matter-crypto matter-cert matter-fabric matter-msg matter-xchg matter-btp matter-pase matter-case matter-im \
             matter-dm matter-root matter-thermostat thermo matter-node
CLI_LIBS  := matter-tlv matter-crypto matter-msg matter-pase
ALL_LIBS  := matter-core $(NODE_LIBS)
INCS     := $(foreach l,$(ALL_LIBS),-I$(L)/$(l)/include) -I$(L)/matter-node/test -I. -I$(OUT) $(MBEDTLS_HOST_CFLAGS)
CFLAGS   := -std=gnu11 -Wall -Wextra -Werror -O1 -g $(INCS)
SRC_DIRS := $(foreach l,$(NODE_LIBS),$(L)/$(l)/src)
vpath %.c . $(SRC_DIRS) $(L)/matter-node/test

NODE_SRC := $(notdir $(foreach d,$(SRC_DIRS),$(wildcard $(d)/*.c))) host_port.c host_mdns.c host_sim.c test_credentials.c node_main.c
CLI_SRC  := $(notdir $(foreach l,$(CLI_LIBS),$(wildcard $(L)/$(l)/src/*.c))) host_port.c mt_test_init.c client_main.c
NODE_OBJ := $(addprefix $(OUT)/obj/,$(NODE_SRC:.c=.o))
CLI_OBJ  := $(addprefix $(OUT)/obj/,$(CLI_SRC:.c=.o))
HDRS     := $(wildcard *.h) $(foreach l,$(ALL_LIBS),$(wildcard $(L)/$(l)/include/*.h $(L)/$(l)/src/*.h)) \
            $(L)/matter-node/test/mt_test_init.h

# Fixed salt and iterations so the node's verifier is stable; rendezvous on-network, discriminator 3840.
SALT_HEX := 000102030405060708090a0b0c0d0e0f

all: $(OUT)/matter-host $(OUT)/matter-host-client $(OUT)/kv-test

$(OUT)/setup_info.h: $(FW)/tools/matter_setup.py Makefile
	@mkdir -p $(OUT)
	$(PYTHON) $(FW)/tools/matter_setup.py $@ --rendezvous onnetwork --passcode 20202021 --discriminator 3840 \
	    --salt-hex $(SALT_HEX) --iterations 1000 > $(OUT)/setup.txt
	@{ echo '#define MH_BANNER \'; \
	   sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/.*/    "&\\n" \\/' $(OUT)/setup.txt; \
	   echo '    ""'; } > $(OUT)/banner.h
$(OUT)/banner.h: $(OUT)/setup_info.h ;

$(OUT)/obj/%.o: %.c $(HDRS) $(OUT)/setup_info.h $(MBEDTLS_HOST_LIB)
	@mkdir -p $(OUT)/obj
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/matter-host: $(NODE_OBJ) $(MBEDTLS_HOST_LIB)
	@echo "  LD   $@"
	@$(CC) $(NODE_OBJ) $(MBEDTLS_HOST_LIB) -o $@

$(OUT)/matter-host-client: $(CLI_OBJ) $(MBEDTLS_HOST_LIB)
	@echo "  LD   $@"
	@$(CC) $(CLI_OBJ) $(MBEDTLS_HOST_LIB) -o $@

$(OUT)/kv-test: $(OUT)/obj/kv_test.o $(OUT)/obj/host_port.o
	@echo "  LD   $@"
	@$(CC) $^ -o $@

run: $(OUT)/matter-host
	$(OUT)/matter-host --kv-dir $(OUT)/kv

NODE_BIN ?= /opt/homebrew/bin/node
e2e: $(OUT)/matter-host
	@NODE_BIN=$(NODE_BIN) sh ./e2e.sh $(OUT)/matter-host

test: all
	@$(OUT)/kv-test
	@sh ./test.sh $(OUT)/matter-host $(OUT)/matter-host-client

clean:
	rm -rf $(OUT)/obj $(OUT)/matter-host $(OUT)/matter-host-client $(OUT)/kv-test $(OUT)/setup_info.h $(OUT)/banner.h $(OUT)/setup.txt

.PHONY: all run test e2e clean
