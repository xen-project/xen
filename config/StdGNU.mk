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

MSGFMT     = msgfmt
MSGMERGE   = msgmerge

# Allow git to be wrappered in the environment
GIT        ?= git

INSTALL      = install
INSTALL_DIR  = $(INSTALL) -d -m0755 -p
INSTALL_DATA = $(INSTALL) -m0644 -p
INSTALL_PROG = $(INSTALL) -m0755 -p

PREFIX ?= /usr
BINDIR = $(PREFIX)/bin
INCLUDEDIR = $(PREFIX)/include
LIBEXEC = $(PREFIX)/lib/xen/bin
SHAREDIR = $(PREFIX)/share
MANDIR = $(SHAREDIR)/man
MAN1DIR = $(MANDIR)/man1
MAN8DIR = $(MANDIR)/man8
SBINDIR = $(PREFIX)/sbin
XENFIRMWAREDIR = $(PREFIX)/lib/xen/boot

PRIVATE_PREFIX = $(LIBDIR)/xen
PRIVATE_BINDIR = $(PRIVATE_PREFIX)/bin

CONFIG_DIR = /etc
XEN_LOCK_DIR = /var/lock
XEN_RUN_DIR = /var/run/xen
XEN_PAGING_DIR = /var/lib/xen/xenpaging

SYSCONFIG_DIR = $(CONFIG_DIR)/$(CONFIG_LEAF_DIR)

XEN_CONFIG_DIR = $(CONFIG_DIR)/xen
XEN_SCRIPT_DIR = $(XEN_CONFIG_DIR)/scripts

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
