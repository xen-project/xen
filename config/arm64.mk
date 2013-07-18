CONFIG_ARM := y
CONFIG_ARM_64 := y
CONFIG_ARM_$(XEN_OS) := y

CONFIG_XEN_INSTALL_SUFFIX :=

CFLAGS += #-marm -march= -mcpu= etc

HAS_PL011 := y

# Use only if calling $(LD) directly.
LDFLAGS_DIRECT += -maarch64elf

CONFIG_LOAD_ADDRESS ?= 0x80000000
