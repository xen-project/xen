subdir-$(CONFIG_X86) += vtd
subdir-$(CONFIG_X86) += amd
subdir-$(CONFIG_X86) += x86
subdir-$(CONFIG_ARM) += arm

obj-y += iommu.o
obj-$(CONFIG_X86) += io.o
obj-$(CONFIG_HAS_PCI) += pci.o
obj-$(CONFIG_HAS_DEVICE_TREE) += device_tree.o
