XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 4

OBJS-y                 += core.o
OBJS-$(CONFIG_Linux)   += common.o
OBJS-$(CONFIG_FreeBSD) += common.o
OBJS-$(CONFIG_SunOS)   += compat.o
OBJS-$(CONFIG_NetBSD)  += compat.o
OBJS-$(CONFIG_MiniOS)  += compat.o

include $(XEN_ROOT)/tools/libs/libs.mk
