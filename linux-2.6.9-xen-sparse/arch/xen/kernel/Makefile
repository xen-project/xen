#
# Makefile for the linux kernel.
#

XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

$(obj)/vmlinux.lds:
	@ln -fsn $(srctree)/arch/$(ARCH)/$(XENARCH)/kernel/vmlinux.lds $@

extra-y += vmlinux.lds

obj-y	:= ctrl_if.o evtchn.o fixup.o reboot.o xen_proc.o empty.o \
           gnttab.o skbuff.o
