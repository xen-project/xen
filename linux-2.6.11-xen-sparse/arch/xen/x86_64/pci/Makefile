#
# Makefile for X86_64 specific PCI routines
#
# Reuse the i386 PCI subsystem
#
XENARCH	:= $(subst ",,$(CONFIG_XENARCH))
CFLAGS	+= -Iarch/$(XENARCH)/pci

CFLAGS += -Iarch/i386/pci

c-obj-y		:= i386.o
c-obj-y		+= fixup.o
c-obj-$(CONFIG_ACPI_PCI)	+= acpi.o
c-obj-y			+= legacy.o common.o
c-xen-obj-$(CONFIG_PCI_DIRECT)+= direct.o
c-xen-obj-y		+= irq.o
# mmconfig has a 64bit special
c-obj-$(CONFIG_PCI_MMCONFIG) += mmconfig.o

c-obj-$(CONFIG_NUMA)	+= k8-bus.o

c-direct-y += ../../i386/pci/direct.o
c-acpi-y   += ../../i386/pci/acpi.o
c-legacy-y += ../../i386/pci/legacy.o
c-irq-y    += ../../i386/pci/irq.o
c-common-y += ../../i386/pci/common.o
c-fixup-y  += ../../i386/pci/fixup.o
c-i386-y  += ../../i386/pci/i386.o

c-link	:=

$(patsubst %.o,$(obj)/%.c,$(c-xen-obj-y) $(c-link)):
	@ln -fsn $(srctree)/arch/xen/i386/pci/$(notdir $@) $@

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-link)):
	@ln -fsn $(srctree)/arch/i386/pci/$(notdir $@) $@

obj-y	+= $(c-obj-y)
obj-y	+= $(c-xen-obj-y)

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-) $(c-link))
