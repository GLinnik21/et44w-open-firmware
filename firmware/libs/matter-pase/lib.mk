# Matter PASE, device (responder / SPAKE2+ verifier) side: PBKDFParamRequest/Response, Pake1-3,
# session key derivation, StatusReport. Pure state machine on top of matter-tlv, matter-crypto and
# matter-msg (mt_sc.h: session parameters, StatusReport);
# uses the stored verifier (w0, L), no PBKDF2 on the device.
# Host test: make -C libs/matter-pase/test
LIBS += matter_pase
matter_pase_INC  := $(d)/include
matter_pase_SRC  := $(wildcard $(d)/src/*.c)
matter_pase_DEPS := matter_core matter_tlv matter_msg matter_crypto mbedtls
