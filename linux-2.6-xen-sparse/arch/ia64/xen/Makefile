#
# Makefile for Xen components
#

obj-y := hypercall.o xenivt.o xenentry.o xensetup.o xenpal.o xenhpski.o xenconsole.o xen_ksyms.o

obj-$(CONFIG_XEN_IA64_DOM0_VP) += hypervisor.o pci-dma-xen.o
pci-dma-xen-$(CONFIG_XEN_IA64_DOM0_VP) := ../../i386/kernel/pci-dma-xen.o