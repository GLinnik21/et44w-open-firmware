# Matter message layer: message / protocol header codec, secure-session AES-CCM seal/open in place,
# message-counter dedup window and tx counters, and the Secure Channel pieces PASE and CASE share (mt_sc.h:
# session parameters, StatusReport). Pure C11 on top of matter-crypto and matter-tlv (no SDK/OS).
# Host test: make -C libs/matter-msg/test
LIBS += matter_msg
matter_msg_INC  := $(d)/include
matter_msg_SRC  := $(wildcard $(d)/src/*.c)
matter_msg_DEPS := matter_core matter_tlv matter_crypto mbedtls
