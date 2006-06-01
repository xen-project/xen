#
# Makefile for the linux kernel.
#

obj-y := evtchn.o gnttab.o features.o

obj-$(CONFIG_PROC_FS)		+= xen_proc.o
obj-$(CONFIG_SYSFS)		+= hypervisor_sysfs.o
obj-$(CONFIG_HOTPLUG_CPU)	+= cpu_hotplug.o
obj-$(CONFIG_XEN_SYSFS)		+= xen_sysfs.o
obj-$(CONFIG_IA64)		+= xenia64_init.o
obj-$(CONFIG_XEN_SKBUFF)	+= skbuff.o
obj-$(CONFIG_XEN_REBOOT)	+= reboot.o
obj-$(CONFIG_XEN_SMPBOOT)	+= smpboot.o
