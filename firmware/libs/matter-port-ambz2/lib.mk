# Matter port for Realtek AmebaZ2 (L2b): Matter task, UDP, mDNS records, clock, entropy, the Matter store (DCT2 in
# the `matter` region), Network Commissioning over wifi-sta, BLE over btp-port-ambz2, boot / safe-mode bookkeeping.
# See include/mtp_port.h.
# Host tests of the pure parts (store_kv, boot_policy): make -C libs/matter-port-ambz2/test
ifeq ($(MATTER),1)
LIBS += matter_port_ambz2
matter_port_ambz2_INC  := $(d)/include
matter_port_ambz2_SRC  := $(wildcard $(d)/src/*.c)
matter_port_ambz2_DEPS := sdk wifi_sta mbedtls matter_core matter_tlv matter_crypto matter_cert matter_msg \
                          matter_xchg matter_btp matter_pase matter_case matter_fabric matter_im matter_dm matter_root \
                          matter_node btp_port_ambz2
# Refuse DCT flash writes / erases outside the `matter` region (src/store_dct.c).
LDFLAGS += -Wl,--wrap=dct_flash_write -Wl,--wrap=dct_flash_erase
# lwIP's responder holds one service by default; the node advertises up to MT_NODE_MDNS_MAX (commissionable +
# 3 fabrics + a pending one). Only the responder's own object changes; HAP builds don't set MATTER.
lwip_mdns_CFLAGS += -DMDNS_MAX_SERVICES=5
endif
