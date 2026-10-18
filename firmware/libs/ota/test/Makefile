# Host unit tests: make -C libs/ota/test
# ota_key, Ed25519 + SHA-512 (Monocypher, the same files as the firmware's libs/ed25519) and ota_receive on fake
# flash/sockets, against headers made by tools/ota_push.py (vectors.h, regenerate with gen_vectors.py).
CC     ?= cc
OUT    := build
MONOCYPHER := ../../../vendor/Monocypher
include ../../ed25519/sources.mk
MONO_INC := $(addprefix -I$(MONOCYPHER)/,$(ED25519_INC))
MONO_OBJ := $(addprefix $(OUT)/mono/,$(notdir $(ED25519_SRC:.c=.o)))
CFLAGS := -std=c11 -Wall -Wextra -Werror -O1 -g -Ishim -I../include -I../src -I../../tuyamcu/test $(MONO_INC)
SRCS   := ../src/ota_key.c ../src/ota_receive.c fake.c test_ota_key.c test_ota_receive.c test_ed25519.c

all: $(OUT)/ota_test
	@$(OUT)/ota_test

# Monocypher builds with warnings off, as in the firmware.
vpath %.c $(addprefix $(MONOCYPHER)/,$(sort $(dir $(ED25519_SRC))))
$(OUT)/mono/%.o: %.c
	@mkdir -p $(OUT)/mono
	$(CC) -std=c11 -O1 -w $(MONO_INC) -c $< -o $@

$(OUT)/ota_test: $(SRCS) $(MONO_OBJ) $(wildcard *.h shim/*.h shim/*/*.h ../src/*.h)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(SRCS) $(MONO_OBJ) -o $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
