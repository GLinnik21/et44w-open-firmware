# Matter exchange layer: session table (unsecured/PASE/CASE), exchange table, MRP (spec 4.12) and dispatch by
# protocol ID. Pure C11 on top of matter-msg; time, send and randomness are injected.
# Host test: make -C libs/matter-xchg/test
LIBS += matter_xchg
matter_xchg_INC  := $(d)/include
matter_xchg_SRC  := $(wildcard $(d)/src/*.c)
matter_xchg_DEPS := matter_core matter_msg matter_crypto mbedtls
