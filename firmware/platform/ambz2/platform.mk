# Realtek AmebaZ2 (RTL8710C/RTL8720C) platform: CPU flags, link and image packing.
# Included by the top Makefile before any lib.mk.

SDK     ?= vendor/ameba-rtos-z2
PYTHON  ?= ../.venv-flash/bin/python
PLAT    := $(PLATFORM)

CFLAGS  += -march=armv8-m.main+dsp -mthumb -mcmse -mfloat-abi=soft -D__thumb2__ -D__ARM_ARCH_8M_MAIN__=1 \
           -fsigned-char -DCONFIG_PLATFORM_8710C -DCONFIG_BUILD_RAM=1 -DV8M_STKOVF -DCONFIG_SYSTEM_TIME64=0 \
           -include $(PLAT)/compat/newlib_compat.h

LDSCRIPT := $(PLAT)/rtl8710c_ram.ld
LDFLAGS  := -nostartfiles -nodefaultlibs -nostdlib -specs=nosys.specs \
            -Wl,--gc-sections -Wl,--warn-section-align -Wl,--build-id=none -Wl,--use-blx \
            -L$(SDK)/component/soc/realtek/8710c/misc/bsp/ROM
# libc calls are redirected to the ROM implementations (SDK libc_wrap.c).
comma    := ,
WRAPS    := strcat strchr strcmp strncmp strnicmp strcpy strncpy strlcpy strlen strnlen strncat strpbrk \
            strspn strstr strtok strxfrm strsep strtod strtof strtold strtoll strtoul strtoull atoi atoui \
            atol atoul atoull atof malloc realloc calloc free _malloc_r _calloc_r _realloc_r _free_r \
            memcmp memcpy memmove memset printf sprintf puts putc putchar snprintf vsnprintf \
            aesccmp_construct_mic_iv aesccmp_construct_mic_header1 aesccmp_construct_ctr_preload \
            rom_psk_CalcGTK rom_psk_CalcPTK aes_80211_encrypt aes_80211_decrypt AES_UnWRAP
# ULA source address fallback (src/lwip_ula_route.c).
WRAPS    += ip6_select_source_address
LDFLAGS  += $(addprefix -Wl$(comma)-wrap$(comma),$(WRAPS))
SDKLIB   := $(SDK)/component/soc/realtek/8710c/misc/bsp/lib/common/GCC
LDLIBS   := $(SDK)/component/soc/realtek/8710c/fwlib/lib/lib/hal_pmc.a \
            -Wl,--start-group -L$(SDKLIB) -l_soc_is -l_wlan -l_dct -l_wps -l_eap -Wl,--end-group

IMAGE    := $(OUT)/image_flash_is.0x000000.bin
$(IMAGE): $(OUT)/app.axf
	@$(PYTHON) tools/pack_image.py $< $(SDK)/component/soc/realtek/8710c/misc/bsp/image/bootloader.axf $(TC)
