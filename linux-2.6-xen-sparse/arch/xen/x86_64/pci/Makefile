#
# Makefile for X86_64 specific PCI routines
#
# Reuse the i386 PCI subsystem
#
XENARCH	:= $(subst ",,$(CONFIG_XENARCH))
CFLAGS	+= -Iarch/$(XENARCH)/pci

CFLAGS += -Iarch/i386/pci

c-i386-obj-y		:= i386.o
c-i386-obj-y		+= fixup.o
c-i386-obj-$(CONFIG_ACPI_PCI)	+= acpi.o
c-i386-obj-y			+= legacy.o common.o
c-i386-obj-$(CONFIG_PCI_DIRECT)+= direct.o
c-xen-obj-y		+= irq.o
# mmconfig has a 64bit special
c-obj-$(CONFIG_PCI_MMCONFIG) += mmconfig.o

c-obj-$(CONFIG_NUMA)	+= k8-bus.o

c-link	:=

$(patsubst %.o,$(obj)/%.c,$(c-xen-obj-y)):
	@ln -fsn $(srctree)/arch/xen/i386/pci/$(notdir $@) $@

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-link)):
	@ln -fsn $(srctree)/arch/x86_64/pci/$(notdir $@) $@

$(patsubst %.o,$(obj)/%.c,$(c-i386-obj-y)):
	@ln -fsn $(srctree)/arch/i386/pci/$(notdir $@) $@

# Make sure irq.o gets linked in before common.o
obj-y	+= $(patsubst common.o,$(c-xen-obj-y) common.o,$(c-i386-obj-y))
obj-y	+= $(c-obj-y)

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-) $(c-link))
clean-files += $(patsubst %.o,%.c,$(c-i386-obj-y) $(c-i386-obj-))
clean-files += $(patsubst %.o,%.c,$(c-xen-obj-y) $(c-xen-obj-))
