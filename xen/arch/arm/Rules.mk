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

CFLAGS-$(HAS_GICV3) += -DHAS_GICV3

EARLY_PRINTK := n

ifeq ($(debug),y)

# See docs/misc/arm/early-printk.txt for syntax

EARLY_PRINTK_brcm           := 8250,0xF040AB00,2
EARLY_PRINTK_dra7           := 8250,0x4806A000,2
EARLY_PRINTK_fastmodel      := pl011,0x1c090000,115200
EARLY_PRINTK_exynos5250     := exynos4210,0x12c20000
EARLY_PRINTK_hip04-d01      := 8250,0xE4007000,2
EARLY_PRINTK_juno           := pl011,0x7ff80000
EARLY_PRINTK_lager          := scif,0xe6e60000
EARLY_PRINTK_midway         := pl011,0xfff36000
EARLY_PRINTK_omap5432       := 8250,0x48020000,2
EARLY_PRINTK_seattle        := pl011,0xe1010000
EARLY_PRINTK_sun6i          := 8250,0x01c28000,2
EARLY_PRINTK_sun7i          := 8250,0x01c28000,2
EARLY_PRINTK_thunderx       := pl011,0x87e024000000
EARLY_PRINTK_vexpress       := pl011,0x1c090000
EARLY_PRINTK_xgene-mcdivitt := 8250,0x1c021000,2
EARLY_PRINTK_xgene-storm    := 8250,0x1c020000,2
EARLY_PRINTK_zynqmp         := cadence,0xff000000

ifneq ($(EARLY_PRINTK_$(CONFIG_EARLY_PRINTK)),)
EARLY_PRINTK_CFG := $(subst $(comma), ,$(EARLY_PRINTK_$(CONFIG_EARLY_PRINTK)))
else
EARLY_PRINTK_CFG := $(subst $(comma), ,$(CONFIG_EARLY_PRINTK))
endif

# Extract configuration from string
EARLY_PRINTK_INC := $(word 1,$(EARLY_PRINTK_CFG))
EARLY_UART_BASE_ADDRESS := $(word 2,$(EARLY_PRINTK_CFG))

# UART specific options
ifeq ($(EARLY_PRINTK_INC),8250)
EARLY_UART_REG_SHIFT := $(word 3,$(EARLY_PRINTK_CFG))
endif
ifeq ($(EARLY_PRINTK_INC),pl011)
ifneq ($(word 3,$(EARLY_PRINTK_CFG)),)
EARLY_PRINTK_INIT_UART := y
EARLY_PRINTK_BAUD := $(word 3,$(EARLY_PRINTK_CFG))
endif
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
