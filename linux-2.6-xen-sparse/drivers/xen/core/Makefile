#
# Makefile for the linux kernel.
#

obj-y   := evtchn.o reboot.o gnttab.o features.o

obj-$(CONFIG_PROC_FS) += xen_proc.o
obj-$(CONFIG_NET)     += skbuff.o
obj-$(CONFIG_SMP)     += smpboot.o
obj-$(CONFIG_SYSFS)   += hypervisor_sysfs.o
obj-$(CONFIG_XEN_SYSFS) += xen_sysfs.o
