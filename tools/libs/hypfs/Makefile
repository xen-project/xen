XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

MAJOR    = 1
MINOR    = 0
version-script := libxenhypfs.map

LDLIBS += -lz

OBJS-y += core.o

include ../libs.mk
