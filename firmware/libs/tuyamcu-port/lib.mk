# TuyaMCU platform glue: UART0 (PA_14 TX / PA_13 RX) + one FreeRTOS task driving the tuyamcu core.
LIBS += tuyamcu_port
tuyamcu_port_INC  := $(d)/include
tuyamcu_port_SRC  := $(wildcard $(d)/src/*.c)
tuyamcu_port_DEPS := sdk tuyamcu
