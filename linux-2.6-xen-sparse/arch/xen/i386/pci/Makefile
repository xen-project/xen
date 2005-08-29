XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

CFLAGS	+= -Iarch/$(XENARCH)/pci

c-obj-y				:= i386.o

#c-obj-$(CONFIG_PCI_BIOS)		+= pcbios.o
c-obj-$(CONFIG_PCI_MMCONFIG)	+= mmconfig.o
c-obj-$(CONFIG_PCI_DIRECT)	+= direct.o

c-pci-y				:= fixup.o
c-pci-$(CONFIG_ACPI_PCI)	+= acpi.o
c-pci-y				+= legacy.o
# Make sure irq.o gets linked in after legacy.o
l-pci-y				+= irq.o

c-pci-$(CONFIG_X86_VISWS)	:= visws.o fixup.o
pci-$(CONFIG_X86_VISWS)		:=
c-pci-$(CONFIG_X86_NUMAQ)	:= numa.o
l-pci-$(CONFIG_X86_NUMAQ)	:= irq.o

obj-y				+= $(pci-y)
c-obj-y				+= $(c-pci-y) common.o

c-link	:=

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-link)):
	@ln -fsn $(srctree)/arch/i386/pci/$(notdir $@) $@

# Make sure irq.o gets linked in before common.o
obj-y	+= $(patsubst common.o,$(l-pci-y) common.o,$(c-obj-y))

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-) $(c-link))
