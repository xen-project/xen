obj-y				:= i386.o init.o

obj-$(CONFIG_PCI_BIOS)		+= pcbios.o
obj-$(CONFIG_PCI_MMCONFIG)	+= mmconfig.o direct.o
obj-$(CONFIG_PCI_DIRECT)	+= direct.o

# pcifront should be after pcbios.o, mmconfig.o, and direct.o as it should only
# take over if direct access to the PCI bus is unavailable
obj-$(CONFIG_XEN_PCIDEV_FRONTEND)	+= pcifront.o

pci-y				:= fixup.o
pci-$(CONFIG_ACPI)		+= acpi.o
pci-y				+= legacy.o irq.o

pci-$(CONFIG_X86_VISWS)		:= visws.o fixup.o
pci-$(CONFIG_X86_NUMAQ)		:= numa.o irq.o

obj-y				+= $(pci-y) common.o

ifdef CONFIG_XEN
include $(srctree)/scripts/Makefile.xen
obj-y := $(call cherrypickxen, $(obj-y))
endif
