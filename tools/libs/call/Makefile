XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 3

SRCS-y                 += core.c buffer.c
SRCS-$(CONFIG_Linux)   += linux.c
SRCS-$(CONFIG_FreeBSD) += freebsd.c
SRCS-$(CONFIG_SunOS)   += solaris.c
SRCS-$(CONFIG_NetBSD)  += netbsd.c
SRCS-$(CONFIG_MiniOS)  += minios.c

include $(XEN_ROOT)/tools/libs/libs.mk
