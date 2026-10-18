# Network log: console tee into a RAM ring + one-client TCP server (port NETLOG_PORT). See include/netlog.h.
LIBS += netlog
netlog_INC  := $(d)/include
netlog_SRC  := $(wildcard $(d)/src/*.c)
netlog_DEPS := sdk net_listen
