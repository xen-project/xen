CONFIG_X86 := y
CONFIG_X86_$(XEN_OS) := y

CONFIG_HVM := y
CONFIG_MIGRATE := y
CONFIG_XCUTILS := y
CONFIG_IOEMU := y

CFLAGS += -m32 -march=i686
LIBDIR := lib

# Use only if calling $(LD) directly.
LDFLAGS_DIRECT += -melf_i386
