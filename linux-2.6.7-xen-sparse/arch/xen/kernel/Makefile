#
# Makefile for the linux kernel.
#

XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

$(obj)/vmlinux.lds.s: arch/$(ARCH)/$(XENARCH)/kernel/vmlinux.lds.s
	@ln -fsn $(srctree)/arch/$(ARCH)/$(XENARCH)/kernel/vmlinux.lds.s $@

extra-y += vmlinux.lds.s

obj-y	:= ctrl_if.o process.o reboot.o empty.o
