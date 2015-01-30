CONFIG_X86 := y
CONFIG_X86_64 := y
CONFIG_X86_$(XEN_OS) := y

CONFIG_COMPAT := y
CONFIG_HVM := y
CONFIG_MIGRATE := y
CONFIG_XCUTILS := y

HAS_MEM_ACCESS := y
HAS_MEM_PAGING := y
HAS_MEM_SHARING := y

CONFIG_XEN_INSTALL_SUFFIX := .gz

CFLAGS += -m64

SunOS_LIBDIR = $(SunOS_LIBDIR_x86_64)

EFI_DIR ?= /usr/lib64/efi

# Use only if calling $(LD) directly.
ifeq ($(XEN_OS),OpenBSD)
LDFLAGS_DIRECT += -melf_x86_64_obsd
else
ifeq ($(XEN_OS),FreeBSD)
LDFLAGS_DIRECT += -melf_x86_64_fbsd
else
LDFLAGS_DIRECT += -melf_x86_64
endif
endif

IOEMU_CPU_ARCH ?= x86_64
