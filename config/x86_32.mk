CONFIG_X86 := y
CONFIG_X86_32 := y

CONFIG_MIGRATE := y
CONFIG_XCUTILS := y

CFLAGS += -m32 -march=i686

# Use only if calling $(LD) directly.
LDFLAGS_DIRECT += -melf_i386$(XEN_ELF_SUB_FLAVOR)

IOEMU_CPU_ARCH ?= i386
