#
# Makefile for the PCI bus specific drivers.
#

include $(BASEDIR)/Rules.mk

OBJS := pci.o quirks.o names.o setup-res.o

#obj-$(CONFIG_PCI) += pci.o quirks.o compat.o names.o
#obj-$(CONFIG_PROC_FS) += proc.o

#ifndef CONFIG_SPARC64
#obj-$(CONFIG_PCI) += setup-res.o
#endif

#
# Some architectures use the generic PCI setup functions
#
#obj-$(CONFIG_ALPHA) += setup-bus.o setup-irq.o
#obj-$(CONFIG_ARM) += setup-bus.o setup-irq.o
#obj-$(CONFIG_PARISC) += setup-bus.o
#obj-$(CONFIG_SUPERH) += setup-bus.o setup-irq.o
#obj-$(CONFIG_ALL_PPC) += setup-bus.o
#obj-$(CONFIG_DDB5476) += setup-bus.o
#obj-$(CONFIG_SGI_IP27) += setup-irq.o

#ifndef CONFIG_X86
#obj-y += syscall.o
#endif

default: driver.o
driver.o: $(OBJS)
	$(LD) $(LDFLAGS) -r -o driver.o $(OBJS)

clean:
	rm -f *.o *~ core gen-devlist classlist.h devlist.h

names.o: names.c devlist.h classlist.h

devlist.h classlist.h: pci.ids gen-devlist
	./gen-devlist <pci.ids

gen-devlist: gen-devlist.c
	$(HOSTCC) $(HOSTCFLAGS) -o gen-devlist gen-devlist.c

