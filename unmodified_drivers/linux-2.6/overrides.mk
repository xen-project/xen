# Hack: we need to use the config which was used to build the kernel,
# except that that won't have the right headers etc., so duplicate
# some of the mach-xen infrastructure in here.
#
# (i.e. we need the native config for things like -mregparm, but
# a Xen kernel to find the right headers)
EXTRA_CFLAGS += -D__XEN_INTERFACE_VERSION__=0x00030205
EXTRA_CFLAGS += -DCONFIG_XEN_COMPAT=0xffffff
EXTRA_CFLAGS += -I$(M)/include -I$(M)/compat-include -DHAVE_XEN_PLATFORM_COMPAT_H
ifeq ($(ARCH),ia64)
  EXTRA_CFLAGS += -DCONFIG_VMX_GUEST
endif

EXTRA_CFLAGS += -include $(srctree)/include/linux/autoconf.h
