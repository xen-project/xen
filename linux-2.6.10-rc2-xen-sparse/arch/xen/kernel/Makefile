#
# Makefile for the linux kernel.
#

XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

CPPFLAGS_vmlinux.lds += -U$(XENARCH)

$(obj)/vmlinux.lds.S:
	@ln -fsn $(srctree)/arch/$(XENARCH)/kernel/vmlinux.lds.S $@

extra-y += vmlinux.lds

obj-y	:= ctrl_if.o evtchn.o fixup.o reboot.o xen_proc.o gnttab.o skbuff.o devmem.o
