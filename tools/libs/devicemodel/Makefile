XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 3

SRCS-y                 += core.c
SRCS-$(CONFIG_Linux)   += common.c
SRCS-$(CONFIG_FreeBSD) += common.c
SRCS-$(CONFIG_SunOS)   += compat.c
SRCS-$(CONFIG_NetBSD)  += compat.c
SRCS-$(CONFIG_MiniOS)  += compat.c

include $(XEN_ROOT)/tools/libs/libs.mk
