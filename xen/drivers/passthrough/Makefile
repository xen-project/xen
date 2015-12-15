subdir-$(x86) += vtd
subdir-$(x86) += amd
subdir-$(x86_64) += x86
subdir-$(arm) += arm

obj-y += iommu.o
obj-$(x86) += io.o
obj-$(CONFIG_HAS_PCI) += pci.o
obj-$(CONFIG_HAS_DEVICE_TREE) += device_tree.o
