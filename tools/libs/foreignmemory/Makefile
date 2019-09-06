XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 3
LIBNAME  := foreignmemory
USELIBS  := toollog toolcore

SRCS-y                 += core.c
SRCS-$(CONFIG_Linux)   += linux.c
SRCS-$(CONFIG_FreeBSD) += freebsd.c
SRCS-$(CONFIG_SunOS)   += compat.c solaris.c
SRCS-$(CONFIG_NetBSD)  += compat.c netbsd.c
SRCS-$(CONFIG_MiniOS)  += minios.c

include $(XEN_ROOT)/tools/libs/libs.mk

$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENFOREIGNMEMORY)/include
$(PKG_CONFIG_LOCAL): PKG_CONFIG_CFLAGS_LOCAL = $(CFLAGS_xeninclude)
