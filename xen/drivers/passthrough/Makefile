obj-$(CONFIG_X86) += vtd/
obj-$(CONFIG_X86) += amd/
obj-$(CONFIG_X86) += x86/
obj-$(CONFIG_ARM) += arm/

obj-y += iommu.o
obj-$(CONFIG_HAS_PCI) += pci.o
obj-$(CONFIG_HAS_DEVICE_TREE) += device_tree.o

x86-$(CONFIG_HVM) := io.o
obj-$(CONFIG_X86) += $(x86-y)
