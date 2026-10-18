# TuyaMCU protocol core (Wi-Fi module side): frame codec, DP codec, link state machine. Pure C11, no
# SDK/OS includes and no DEPS; all I/O goes through callbacks. Host tests: make -C libs/tuyamcu/test
LIBS += tuyamcu
tuyamcu_INC := $(d)/include
tuyamcu_SRC := $(wildcard $(d)/src/*.c)
