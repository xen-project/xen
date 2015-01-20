XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += $(CFLAGS_libxenctrl)
LDLIBS += $(LDLIBS_libxenctrl)

SUBDIRS-y :=
SUBDIRS-y += include
SUBDIRS-y += lvm
SUBDIRS-y += vhd
SUBDIRS-$(CONFIG_Linux) += drivers
SUBDIRS-$(CONFIG_Linux) += control

clean:
	rm -rf *.a *.so *.o *.rpm $(LIB) *~ $(DEPS) TAGS

distclean: clean

.PHONY: all clean install distclean
all clean install distclean: %: subdirs-%
