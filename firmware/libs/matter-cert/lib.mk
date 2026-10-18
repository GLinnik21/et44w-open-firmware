# Matter operational certificates (TLV decode, TBS rebuild, chain verify) and the NOC CSR builder.
# Pure C11 on top of matter-tlv and matter-crypto; no X.509 parser, no mbedtls asn1.
# Host test: make -C libs/matter-cert/test
ifeq ($(MATTER),1)
LIBS += matter_cert
matter_cert_INC  := $(d)/include
matter_cert_SRC  := $(wildcard $(d)/src/*.c)
matter_cert_DEPS := matter_core matter_tlv matter_crypto mbedtls
endif
