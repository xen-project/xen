########################################
# arm-specific definitions

#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#

HAS_DEVICE_TREE := y
HAS_VIDEO := y
HAS_ARM_HDLCD := y
HAS_PASSTHROUGH := y
HAS_PDX := y

CFLAGS += -I$(BASEDIR)/include

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))
$(call cc-option-add,CFLAGS,CC,-Wnested-externs)

arm := y

ifeq ($(TARGET_SUBARCH),arm32)
# Prevent floating-point variables from creeping into Xen.
CFLAGS += -msoft-float
CFLAGS += -mcpu=cortex-a15
arm32 := y
arm64 := n
endif

ifeq ($(TARGET_SUBARCH),arm64)
CFLAGS += -mcpu=generic
CFLAGS += -mgeneral-regs-only # No fp registers etc
arm32 := n
arm64 := y
endif

ifneq ($(call cc-option,$(CC),-fvisibility=hidden,n),n)
CFLAGS += -DGCC_HAS_VISIBILITY_ATTRIBUTE
endif

EARLY_PRINTK := n

ifeq ($(debug),y)

# Early printk for versatile express
ifeq ($(CONFIG_EARLY_PRINTK), vexpress)
EARLY_PRINTK_INC := pl011
EARLY_UART_BASE_ADDRESS := 0x1c090000
endif
ifeq ($(CONFIG_EARLY_PRINTK), fastmodel)
EARLY_PRINTK_INC := pl011
EARLY_PRINTK_INIT_UART := y
EARLY_PRINTK_BAUD := 115200
EARLY_UART_BASE_ADDRESS := 0x1c090000
endif
ifeq ($(CONFIG_EARLY_PRINTK), exynos5250)
EARLY_PRINTK_INC := exynos4210
EARLY_UART_BASE_ADDRESS := 0x12c20000
endif
ifeq ($(CONFIG_EARLY_PRINTK), midway)
EARLY_PRINTK_INC := pl011
EARLY_UART_BASE_ADDRESS := 0xfff36000
endif
ifeq ($(CONFIG_EARLY_PRINTK), omap5432)
EARLY_PRINTK_INC := 8250
EARLY_UART_BASE_ADDRESS := 0x48020000
EARLY_UART_REG_SHIFT := 2
endif
ifeq ($(CONFIG_EARLY_PRINTK), dra7)
EARLY_PRINTK_INC := 8250
EARLY_UART_BASE_ADDRESS := 0x4806A000
EARLY_UART_REG_SHIFT := 2
endif
ifeq ($(CONFIG_EARLY_PRINTK), sun6i)
EARLY_PRINTK_INC := 8250
EARLY_UART_BASE_ADDRESS := 0x01c28000
EARLY_UART_REG_SHIFT := 2
endif
ifeq ($(CONFIG_EARLY_PRINTK), sun7i)
EARLY_PRINTK_INC := 8250
EARLY_UART_BASE_ADDRESS := 0x01c28000
EARLY_UART_REG_SHIFT := 2
endif
ifeq ($(CONFIG_EARLY_PRINTK), brcm)
EARLY_PRINTK_INC := 8250
EARLY_UART_BASE_ADDRESS := 0xF040AB00
EARLY_UART_REG_SHIFT := 2
endif
ifeq ($(CONFIG_EARLY_PRINTK), xgene-storm)
EARLY_PRINTK_INC := 8250
EARLY_UART_BASE_ADDRESS := 0x1c020000
EARLY_UART_REG_SHIFT := 2
endif
ifeq ($(CONFIG_EARLY_PRINTK), xgene-mcdivitt)
EARLY_PRINTK_INC := 8250
EARLY_UART_BASE_ADDRESS := 0x1c021000
EARLY_UART_REG_SHIFT := 2
endif
ifeq ($(CONFIG_EARLY_PRINTK), juno)
EARLY_PRINTK_INC := pl011
EARLY_UART_BASE_ADDRESS := 0x7ff80000
endif
ifeq ($(CONFIG_EARLY_PRINTK), hip04-d01)
EARLY_PRINTK_INC := 8250
EARLY_UART_BASE_ADDRESS := 0xE4007000
EARLY_UART_REG_SHIFT := 2
endif
ifeq ($(CONFIG_EARLY_PRINTK), seattle)
EARLY_PRINTK_INC := pl011
EARLY_UART_BASE_ADDRESS := 0xe1010000
endif

ifneq ($(EARLY_PRINTK_INC),)
EARLY_PRINTK := y
endif

CFLAGS-$(EARLY_PRINTK) += -DCONFIG_EARLY_PRINTK
CFLAGS-$(EARLY_PRINTK_INIT_UART) += -DEARLY_PRINTK_INIT_UART
CFLAGS-$(EARLY_PRINTK) += -DEARLY_PRINTK_INC=\"debug-$(EARLY_PRINTK_INC).inc\"
CFLAGS-$(EARLY_PRINTK) += -DEARLY_PRINTK_BAUD=$(EARLY_PRINTK_BAUD)
CFLAGS-$(EARLY_PRINTK) += -DEARLY_UART_BASE_ADDRESS=$(EARLY_UART_BASE_ADDRESS)
CFLAGS-$(EARLY_PRINTK) += -DEARLY_UART_REG_SHIFT=$(EARLY_UART_REG_SHIFT)

else # !debug

ifneq ($(CONFIG_EARLY_PRINTK),)
# Early printk is dependant on a debug build.
$(error CONFIG_EARLY_PRINTK enabled for non-debug build)
endif

endif
