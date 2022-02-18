########################################
# arm-specific definitions

CFLAGS += -I$(BASEDIR)/include
CFLAGS += -I$(BASEDIR)/arch/$(TARGET_ARCH)/include

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))
$(call cc-option-add,CFLAGS,CC,-Wnested-externs)

# Prevent floating-point variables from creeping into Xen.
CFLAGS-$(CONFIG_ARM_32) += -msoft-float
CFLAGS-$(CONFIG_ARM_32) += -mcpu=cortex-a15

CFLAGS-$(CONFIG_ARM_64) += -mcpu=generic
CFLAGS-$(CONFIG_ARM_64) += -mgeneral-regs-only # No fp registers etc
$(call cc-option-add,CFLAGS-$(CONFIG_ARM_64),CC,-mno-outline-atomics)

ifneq ($(filter command line environment,$(origin CONFIG_EARLY_PRINTK)),)
    $(error You must use 'make menuconfig' to enable/disable early printk now)
endif

ifeq ($(CONFIG_ARM64_ERRATUM_843419),y)
    ifeq ($(call ld-option, --fix-cortex-a53-843419),n)
        $(warning ld does not support --fix-cortex-a53-843419; xen may be susceptible to erratum)
    else
        LDFLAGS += --fix-cortex-a53-843419
    endif
endif

ALL_OBJS-y := arch/arm/$(TARGET_SUBARCH)/head.o $(ALL_OBJS-y)
