CONFIG_X86 := y
CONFIG_X86_32 := y
CONFIG_X86_$(XEN_OS) := y

CONFIG_HVM := y
CONFIG_MIGRATE := y
CONFIG_XCUTILS := y
CONFIG_IOEMU := y

CFLAGS += -m32 -march=i686
LIBDIR := lib

# Use only if calling $(LD) directly.
ifeq ($(XEN_OS),OpenBSD)
LDFLAGS_DIRECT += -melf_i386_obsd
else
LDFLAGS_DIRECT += -melf_i386
endif
