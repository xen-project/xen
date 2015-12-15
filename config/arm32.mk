CONFIG_ARM := y
CONFIG_ARM_32 := y
CONFIG_ARM_$(XEN_OS) := y

CONFIG_XEN_INSTALL_SUFFIX :=

# -march= -mcpu=

# Explicitly specifiy 32-bit ARM ISA since toolchain default can be -mthumb:
CFLAGS += -marm

# Use only if calling $(LD) directly.
LDFLAGS_DIRECT += -EL

CONFIG_LOAD_ADDRESS ?= 0x80000000

IOEMU_CPU_ARCH ?= arm
