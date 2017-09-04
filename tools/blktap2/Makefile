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
	rm -rf *.a *.so *.o *.rpm $(LIB) *~ $(DEPS_RM) TAGS

distclean: clean

.PHONY: all clean install distclean uninstall
all clean install distclean uninstall: %: subdirs-%
