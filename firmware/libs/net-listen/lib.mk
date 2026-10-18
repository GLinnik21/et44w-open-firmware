# One TCP listener helper shared by the socket servers (ota, netlog, httpd).
LIBS += net_listen
net_listen_INC  := $(d)/include
net_listen_SRC  := $(wildcard $(d)/src/*.c)
net_listen_DEPS := sdk
