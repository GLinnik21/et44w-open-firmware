# Realtek BLE host stack (closed btgap.a + board glue), only with `make BT=1`. Vendor code, warnings off.
BTSDK := $(SDK)/component/common/bluetooth/realtek/sdk
LIBS += bt
bt_DEPS   := sdk
bt_DEFS   := -DCONFIG_BT=1
bt_CFLAGS := -w
bt_INC := $(BTSDK) $(BTSDK)/inc $(BTSDK)/inc/app $(BTSDK)/inc/bluetooth/gap $(BTSDK)/inc/bluetooth/profile \
  $(BTSDK)/inc/bluetooth/profile/server $(BTSDK)/inc/os $(BTSDK)/inc/platform $(BTSDK)/inc/stack \
  $(BTSDK)/board/amebaz2/lib/GCC $(BTSDK)/board/amebaz2/src $(BTSDK)/board/amebaz2/src/hci \
  $(BTSDK)/board/amebaz2/src/vendor_cmd $(BTSDK)/board/common/inc $(SDK)/component/common/file_system/ftl
bt_SRC := $(addprefix $(BTSDK)/board/amebaz2/src/,hci/bt_fwconfig.c hci/bt_normal_patch.c hci/bt_mp_patch.c \
            hci/hci_board.c hci/hci_uart.c platform_utils.c rtk_coex.c trace_uart.c vendor_cmd/vendor_cmd.c) \
          $(addprefix $(BTSDK)/board/common/src/,bt_uart_bridge.c cycle_queue.c hci_adapter.c hci_process.c trace_task.c) \
          $(BTSDK)/board/common/os/freertos/osif_freertos.c \
          $(SDK)/component/common/file_system/ftl/ftl.c
LDLIBS += $(BTSDK)/board/amebaz2/lib/GCC/btgap.a
# The probe's health check connects to its own OTA listener on 127.0.0.1 (global: lwIP is built by the sdk lib).
CFLAGS += -DLWIP_NETIF_LOOPBACK=1 -DLWIP_HAVE_LOOPIF=1
