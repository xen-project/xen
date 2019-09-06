XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 2
LIBNAME  := gnttab
USELIBS  := toollog toolcore

SRCS-GNTTAB            += gnttab_core.c
SRCS-GNTSHR            += gntshr_core.c

SRCS-$(CONFIG_Linux)   += $(SRCS-GNTTAB) $(SRCS-GNTSHR) linux.c
SRCS-$(CONFIG_MiniOS)  += $(SRCS-GNTTAB) gntshr_unimp.c minios.c
SRCS-$(CONFIG_FreeBSD) += $(SRCS-GNTTAB) $(SRCS-GNTSHR) freebsd.c
SRCS-$(CONFIG_SunOS)   += gnttab_unimp.c gntshr_unimp.c
SRCS-$(CONFIG_NetBSD)  += gnttab_unimp.c gntshr_unimp.c

include $(XEN_ROOT)/tools/libs/libs.mk

$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENGNTTAB)/include
$(PKG_CONFIG_LOCAL): PKG_CONFIG_CFLAGS_LOCAL = $(CFLAGS_xeninclude)
