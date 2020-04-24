########################################
# arm-specific definitions

CFLAGS += -I$(BASEDIR)/include

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))
$(call cc-option-add,CFLAGS,CC,-Wnested-externs)

# Prevent floating-point variables from creeping into Xen.
CFLAGS-$(CONFIG_ARM_32) += -msoft-float
CFLAGS-$(CONFIG_ARM_32) += -mcpu=cortex-a15

CFLAGS-$(CONFIG_ARM_64) += -mcpu=generic
CFLAGS-$(CONFIG_ARM_64) += -mgeneral-regs-only # No fp registers etc

ifneq ($(filter command line environment,$(origin CONFIG_EARLY_PRINTK)),)
    $(error You must use 'make menuconfig' to enable/disable early printk now)
endif
