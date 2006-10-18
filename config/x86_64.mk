CONFIG_X86 := y
CONFIG_X86_$(XEN_OS) := y

CONFIG_HVM := y
CONFIG_MIGRATE := y
CONFIG_XCUTILS := y
CONFIG_IOEMU := y

CFLAGS += -m64
LIBDIR = $(LIB64DIR)

# Use only if calling $(LD) directly.
LDFLAGS_DIRECT += -melf_x86_64
