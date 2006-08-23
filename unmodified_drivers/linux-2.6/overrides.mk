# Hack: we need to use the config which was used to build the kernel,
# except that that won't have the right headers etc., so duplicate
# some of the mach-xen infrastructure in here.
#
# (i.e. we need the native config for things like -mregparm, but
# a Xen kernel to find the right headers)
EXTRA_CFLAGS += -DCONFIG_VMX -DCONFIG_VMX_GUEST -DCONFIG_X86_XEN
EXTRA_CFLAGS += -DCONFIG_XEN_SHADOW_MODE -DCONFIG_XEN_SHADOW_TRANSLATE
EXTRA_CFLAGS += -DCONFIG_XEN_BLKDEV_GRANT -DXEN_EVTCHN_MASK_OPS
EXTRA_CFLAGS += -DCONFIG_XEN_NETDEV_GRANT_RX -DCONFIG_XEN_NETDEV_GRANT_TX
EXTRA_CFLAGS += -D__XEN_INTERFACE_VERSION__=0x00030202
EXTRA_CFLAGS += -I$(M)/include
