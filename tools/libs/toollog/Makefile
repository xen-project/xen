XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR	= 1
MINOR	= 0
LIBNAME  := toollog

SRCS-y	+= xtl_core.c
SRCS-y	+= xtl_logger_stdio.c

include $(XEN_ROOT)/tools/libs/libs.mk

$(PKG_CONFIG_LOCAL): PKG_CONFIG_INCDIR = $(XEN_LIBXENTOOLLOG)/include
