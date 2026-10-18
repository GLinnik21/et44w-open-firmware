# Minimal one-handler HTTP server (see include/httpd.h). src/http_parse.c is pure and host-tested:
# make -C libs/httpd/test
LIBS += httpd
httpd_INC  := $(d)/include
httpd_SRC  := $(wildcard $(d)/src/*.c)
httpd_DEPS := sdk net_listen
