########################################
# arm-specific definitions

#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#

CFLAGS += -I$(BASEDIR)/include

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))
$(call cc-option-add,CFLAGS,CC,-Wnested-externs)

# Prevent floating-point variables from creeping into Xen.
CFLAGS-$(CONFIG_ARM_32) += -msoft-float
CFLAGS-$(CONFIG_ARM_32) += -mcpu=cortex-a15

CFLAGS-$(CONFIG_ARM_64) += -mcpu=generic
CFLAGS-$(CONFIG_ARM_64) += -mgeneral-regs-only # No fp registers etc

EARLY_PRINTK := n

ifeq ($(CONFIG_DEBUG),y)

# See docs/misc/arm/early-printk.txt for syntax

EARLY_PRINTK_brcm           := 8250,0xF040AB00,2
EARLY_PRINTK_dra7           := 8250,0x4806A000,2
EARLY_PRINTK_fastmodel      := pl011,0x1c090000,115200
EARLY_PRINTK_exynos5250     := exynos4210,0x12c20000
EARLY_PRINTK_hikey960       := pl011,0xfff32000
EARLY_PRINTK_juno           := pl011,0x7ff80000
EARLY_PRINTK_lager          := scif,0xe6e60000
EARLY_PRINTK_midway         := pl011,0xfff36000
EARLY_PRINTK_mvebu          := mvebu,0xd0012000
EARLY_PRINTK_omap5432       := 8250,0x48020000,2
EARLY_PRINTK_rcar3          := scif,0xe6e88000
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
ifeq ($(EARLY_PRINTK_INC),scif)
ifneq ($(word 3,$(EARLY_PRINTK_CFG)),)
CFLAGS-y += -DEARLY_PRINTK_VERSION_$(word 3,$(EARLY_PRINTK_CFG))
else
CFLAGS-y += -DEARLY_PRINTK_VERSION_NONE
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

else # !CONFIG_DEBUG

ifneq ($(CONFIG_EARLY_PRINTK),)
# Early printk is dependant on a debug build.
$(error CONFIG_EARLY_PRINTK enabled for non-debug build)
endif

endif
