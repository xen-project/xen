########################################
# arm-specific definitions

#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#

HAS_DEVICE_TREE := y
HAS_VIDEO := y
HAS_ARM_HDLCD := y

CFLAGS += -fno-builtin -fno-common -Wredundant-decls
CFLAGS += -iwithprefix include -Werror -Wno-pointer-arith -pipe
CFLAGS += -I$(BASEDIR)/include

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))
$(call cc-option-add,CFLAGS,CC,-Wnested-externs)

arm := y

ifeq ($(TARGET_SUBARCH),arm32)
# Prevent floating-point variables from creeping into Xen.
CFLAGS += -msoft-float
CFLAGS += -mcpu=cortex-a15 -mfpu=vfpv3 -mfloat-abi=softfp
arm32 := y
arm64 := n
endif

ifeq ($(TARGET_SUBARCH),arm64)
CFLAGS += -mcpu=generic
arm32 := n
arm64 := y
endif

ifneq ($(call cc-option,$(CC),-fvisibility=hidden,n),n)
CFLAGS += -DGCC_HAS_VISIBILITY_ATTRIBUTE
endif

EARLY_PRINTK := n

ifeq ($(debug),y)

# Early printk for versatile express
# TODO handle UART base address from make command line
ifeq ($(CONFIG_EARLY_PRINTK), vexpress)
EARLY_PRINTK_INC := pl011
EARLY_PRINTK_BAUD := 38400
endif
ifeq ($(CONFIG_EARLY_PRINTK), exynos5250)
EARLY_PRINTK_INC := exynos4210
EARLY_PRINTK_INIT_UART := y
EARLY_PRINTK_BAUD := 115200
endif

ifneq ($(EARLY_PRINTK_INC),)
EARLY_PRINTK := y
endif

CFLAGS-$(EARLY_PRINTK) += -DEARLY_PRINTK
CFLAGS-$(EARLY_PRINTK_INIT_UART) += -DEARLY_PRINTK_INIT_UART
CFLAGS-$(EARLY_PRINTK) += -DEARLY_PRINTK_INC=\"debug-$(EARLY_PRINTK_INC).inc\"
CFLAGS-$(EARLY_PRINTK) += -DEARLY_PRINTK_BAUD=$(EARLY_PRINTK_BAUD)
endif
