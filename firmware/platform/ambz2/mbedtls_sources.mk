# mbedtls 3.1.0 library sources (file names under $(MBEDTLS)/library) for mbedtls/ambz2_mbedtls_config.h. Shared by
# the firmware build (mbedtls.mk) and the host tests of the pure libs (build/hosttest.mk), so the two can't drift apart.
MBEDTLS_SRC := aes.c asn1parse.c asn1write.c bignum.c ccm.c cipher.c cipher_wrap.c constant_time.c ctr_drbg.c ecdh.c \
  ecdsa.c ecp.c ecp_curves.c hkdf.c md.c platform_util.c sha256.c
