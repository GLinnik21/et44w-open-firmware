# Matter endpoint-0 clusters, one source file each: Basic Information (0x28), General Commissioning (0x30),
# Operational Credentials (0x3E), Access Control (0x1F, plus the spec 6.6.6 access check) and Group Key
# Management (0x3F), plus the control clusters Network Commissioning (0x31, Wi-Fi), General Diagnostics (0x33)
# and Administrator Commissioning (0x3C) behind port interfaces (mt_netctl.h, mt_admin_ops), sharing the commissioning context of include/mt_root_comm.h (fail-safe, session and
# attestation hooks implemented by matter-node). Pure C11 on top of matter-dm and matter-fabric; persistence
# goes through the injected mt_kv_ops (mt_core.h).
# Host test: make -C libs/matter-root/test
LIBS += matter_root
matter_root_INC  := $(d)/include
matter_root_SRC  := $(wildcard $(d)/src/*.c)
matter_root_DEPS := matter_core matter_tlv matter_im matter_dm matter_fabric matter_cert matter_crypto mbedtls
