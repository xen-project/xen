AS         = $(CROSS_COMPILE)gas
LD         = $(CROSS_COMPILE)gld
CC         = $(CROSS_COMPILE)gcc
CPP        = $(CROSS_COMPILE)gcc -E
AR         = $(CROSS_COMPILE)gar
RANLIB     = $(CROSS_COMPILE)granlib
NM         = $(CROSS_COMPILE)gnm
STRIP      = $(CROSS_COMPILE)gstrip
OBJCOPY    = $(CROSS_COMPILE)gobjcopy
OBJDUMP    = $(CROSS_COMPILE)gobjdump
SIZEUTIL   = $(CROSS_COMPILE)gsize

MSGFMT     = gmsgfmt

SHELL      = bash

INSTALL      = ginstall
INSTALL_DIR  = $(INSTALL) -d -m0755 -p
INSTALL_DATA = $(INSTALL) -m0644 -p
INSTALL_PROG = $(INSTALL) -m0755 -p

PREFIX ?= /usr
BINDIR = $(PREFIX)/bin
INCLUDEDIR = $(PREFIX)/include
MANDIR = $(PREFIX)/share/man
MAN1DIR = $(MANDIR)/man1
MAN8DIR = $(MANDIR)/man8
SBINDIR = $(PREFIX)/sbin
XENFIRMWAREDIR = $(LIBDIR)/xen/boot

PRIVATE_PREFIX = $(LIBDIR)/xen
PRIVATE_BINDIR = $(PRIVATE_PREFIX)/bin

ifeq ($(PREFIX),/usr)
CONFIG_DIR = /etc
else
CONFIG_DIR = $(PREFIX)/etc
endif
XEN_CONFIG_DIR = $(CONFIG_DIR)/xen
XEN_SCRIPT_DIR = $(PRIVATE_PREFIX)/scripts

SunOS_LIBDIR = /usr/sfw/lib
SunOS_LIBDIR_x86_64 = /usr/sfw/lib/amd64

SOCKET_LIBS = -lsocket
PTHREAD_LIBS = -lpthread
UTIL_LIBS =
DLOPEN_LIBS = -ldl

SONAME_LDFLAG = -h
SHLIB_LDFLAGS = -R $(SunOS_LIBDIR) -shared

ifneq ($(debug),y)
CFLAGS += -O2 -fno-omit-frame-pointer
else
# Less than -O1 produces bad code and large stack frames
CFLAGS += -O1 -fno-omit-frame-pointer
endif

CFLAGS += -Wa,--divide -D_POSIX_C_SOURCE=200112L -D__EXTENSIONS__

