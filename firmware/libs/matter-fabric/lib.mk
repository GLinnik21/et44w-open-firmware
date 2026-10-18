# Matter fabric table: committed fabrics (RCAC/ICAC/NOC, operational key, IPK, compressed fabric ID,
# label, ACL) plus one RAM-staged pending fabric visible to CASE lookups while the fail-safe is armed.
# Storage is serialised as TLV records through an injected key/value interface (mt_kv_ops); the
# port does the spare-module write and index flip. Pure C11 on top of matter-tlv, matter-cert, matter-crypto.
# Host test: make -C libs/matter-fabric/test
LIBS += matter_fabric
matter_fabric_INC  := $(d)/include
matter_fabric_SRC  := $(wildcard $(d)/src/*.c)
matter_fabric_DEPS := matter_core matter_tlv matter_crypto matter_cert mbedtls
