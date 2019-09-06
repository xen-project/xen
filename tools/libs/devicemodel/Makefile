XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 3
LIBNAME  := devicemodel
USELIBS  := toollog toolcore call

SRCS-y                 += core.c
SRCS-$(CONFIG_Linux)   += linux.c
SRCS-$(CONFIG_FreeBSD) += compat.c
SRCS-$(CONFIG_SunOS)   += compat.c
SRCS-$(CONFIG_NetBSD)  += compat.c
SRCS-$(CONFIG_MiniOS)  += compat.c

include $(XEN_ROOT)/tools/libs/libs.mk

$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENDEVICEMODEL)/include
$(PKG_CONFIG_LOCAL): PKG_CONFIG_CFLAGS_LOCAL = $(CFLAGS_xeninclude)
