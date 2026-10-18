# Matter CASE, responder side: Sigma1 -> Sigma2, Sigma3 verify, session keys. Destination-ID matching over
# committed and pending fabrics, peer NOC chain against the fabric's stored root. Pure state machine on top of
# matter-tlv, matter-crypto, matter-msg (mt_sc.h), matter-cert and matter-fabric; resumption is not supported (always full Sigma2).
# Host test: make -C libs/matter-case/test
LIBS += matter_case
matter_case_INC  := $(d)/include
matter_case_SRC  := $(wildcard $(d)/src/*.c)
matter_case_DEPS := matter_core matter_tlv matter_msg matter_crypto matter_cert matter_fabric mbedtls
