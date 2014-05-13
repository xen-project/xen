subdir-$(x86) += vtd
subdir-$(x86) += amd
subdir-$(x86_64) += x86
subdir-$(arm) += arm

obj-y += iommu.o
obj-$(x86) += io.o
obj-$(HAS_PCI) += pci.o
obj-$(HAS_DEVICE_TREE) += device_tree.o
