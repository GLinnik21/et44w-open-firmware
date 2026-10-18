# Time zones: POSIX TZ rules (fixed offset + optional Mm.w.d DST) and UTC epoch -> local civil time.
# Pure C11, no SDK/OS includes and no DEPS. Host tests: make -C libs/tz/test
LIBS += tz
tz_INC := $(d)/include
tz_SRC := $(wildcard $(d)/src/*.c)
