XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 2

OBJS-y                 += core.o
OBJS-$(CONFIG_Linux)   += linux.o
OBJS-$(CONFIG_FreeBSD) += freebsd.o
OBJS-$(CONFIG_SunOS)   += solaris.o
OBJS-$(CONFIG_NetBSD)  += netbsd.o
OBJS-$(CONFIG_MiniOS)  += minios.o

include $(XEN_ROOT)/tools/libs/libs.mk
