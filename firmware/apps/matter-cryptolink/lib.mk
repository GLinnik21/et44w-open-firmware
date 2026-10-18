# Throwaway link test for the Matter crypto set (make MATTER=1 APP=apps/matter-cryptolink): the
# matter-base wiring plus crypto_link.c, which references every mbedtls function the stack will use.
# Never pushed to a device; its flash delta against matter-base (BT=1) is the crypto cost.
ifneq ($(MATTER),1)
$(error apps/matter-cryptolink needs MATTER=1)
endif
LIBS += app
app_SRC  := apps/matter-base/main.c apps/matter-base/selfcheck.c apps/example-switch/mcu_probe.c \
            $(d)/crypto_link.c $(d)/libs_link.c
app_INC  := $(d) apps/matter-base apps/example-switch
app_DEPS := sdk wifi_sta netlog ota wdog tuyamcu tuyamcu_port ble_probe mbedtls matter_core matter_tlv matter_crypto matter_btp matter_msg matter_cert matter_pase \
            matter_xchg matter_fabric matter_case matter_im matter_dm matter_root matter_thermostat thermo matter_node
app_DEFS := -DCRYPTO_LINK
