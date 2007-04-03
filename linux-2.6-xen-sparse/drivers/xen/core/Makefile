#
# Makefile for the linux kernel.
#

obj-y := evtchn.o gnttab.o features.o reboot.o machine_reboot.o

obj-$(CONFIG_PROC_FS)		+= xen_proc.o
obj-$(CONFIG_SYSFS)		+= hypervisor_sysfs.o
obj-$(CONFIG_HOTPLUG_CPU)	+= cpu_hotplug.o
obj-$(CONFIG_XEN_SYSFS)		+= xen_sysfs.o
obj-$(CONFIG_XEN_SMPBOOT)	+= smpboot.o
obj-$(CONFIG_KEXEC)		+= machine_kexec.o
