# mbedtls 3.1.0 library sources (file names under $(MBEDTLS)/library). Shared by the firmware build
# (mbedtls.mk) and the host tests of the pure libs (build/hosttest.mk), so the two can't drift apart.
MBEDTLS_HAP_SRC := aes.c bignum.c chacha20.c chachapoly.c constant_time.c ecdh.c ecp.c ecp_curves.c \
  hkdf.c md.c pkcs5.c platform_util.c poly1305.c sha1.c sha256.c sha512.c
# Added by the Matter config (ambz2_mbedtls_matter_config.h).
MBEDTLS_MATTER_SRC := asn1parse.c asn1write.c ccm.c cipher.c cipher_wrap.c ctr_drbg.c ecdsa.c
