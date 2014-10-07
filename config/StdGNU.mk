AS         = $(CROSS_COMPILE)as
LD         = $(CROSS_COMPILE)ld
ifeq ($(clang),y)
CC         = $(CROSS_COMPILE)clang
LD_LTO     = $(CROSS_COMPILE)llvm-ld
else
CC         = $(CROSS_COMPILE)gcc
LD_LTO     = $(CROSS_COMPILE)ld
endif
CPP        = $(CC) -E
AR         = $(CROSS_COMPILE)ar
RANLIB     = $(CROSS_COMPILE)ranlib
NM         = $(CROSS_COMPILE)nm
STRIP      = $(CROSS_COMPILE)strip
OBJCOPY    = $(CROSS_COMPILE)objcopy
OBJDUMP    = $(CROSS_COMPILE)objdump
SIZEUTIL   = $(CROSS_COMPILE)size

# Allow git to be wrappered in the environment
GIT        ?= git

INSTALL      = install
INSTALL_DIR  = $(INSTALL) -d -m0755 -p
INSTALL_DATA = $(INSTALL) -m0644 -p
INSTALL_PROG = $(INSTALL) -m0755 -p

BOOT_DIR ?= /boot

SOCKET_LIBS =
UTIL_LIBS = -lutil
DLOPEN_LIBS = -ldl

SONAME_LDFLAG = -soname
SHLIB_LDFLAGS = -shared

ifneq ($(debug),y)
CFLAGS += -O2 -fomit-frame-pointer
else
# Less than -O1 produces bad code and large stack frames
CFLAGS += -O1 -fno-omit-frame-pointer
CFLAGS-$(gcc) += -fno-optimize-sibling-calls
endif

ifeq ($(lto),y)
CFLAGS += -flto
LDFLAGS-$(clang) += -plugin LLVMgold.so
endif
