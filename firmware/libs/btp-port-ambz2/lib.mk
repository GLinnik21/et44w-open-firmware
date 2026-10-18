# BLE side of Matter commissioning on AmebaZ2 (L2b): GATT service 0xFFF6 (C1/C2), advertising, the BLE task and the
# one-way stack teardown. No BTP logic (matter-btp in the node). See include/btp_port.h. MATTER=1 builds set BT=1.
ifeq ($(MATTER),1)
LIBS += btp_port_ambz2
btp_port_ambz2_INC  := $(d)/include
btp_port_ambz2_SRC  := $(wildcard $(d)/src/*.c)
btp_port_ambz2_DEPS := sdk bt
endif
