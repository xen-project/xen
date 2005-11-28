#
# Makefile for the linux kernel.
#

XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

CPPFLAGS_vmlinux.lds += -U$(XENARCH)

$(obj)/vmlinux.lds.S:
	@ln -fsn $(srctree)/arch/$(XENARCH)/kernel/vmlinux.lds.S $@

extra-y += vmlinux.lds

obj-y   := evtchn.o reboot.o gnttab.o

obj-$(CONFIG_PROC_FS) += xen_proc.o
obj-$(CONFIG_NET)     += skbuff.o
obj-$(CONFIG_SMP)     += smpboot.o
