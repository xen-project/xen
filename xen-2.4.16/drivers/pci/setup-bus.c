/*
 *	drivers/pci/setup-bus.c
 *
 * Extruded from code written by
 *      Dave Rusling (david.rusling@reo.mts.dec.com)
 *      David Mosberger (davidm@cs.arizona.edu)
 *	David Miller (davem@redhat.com)
 *
 * Support routines for initializing a PCI subsystem.
 */

/*
 * Nov 2000, Ivan Kokshaysky <ink@jurassic.park.msu.ru>
 *	     PCI-PCI bridges cleanup, sorted resource allocation
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/cache.h>
#include <linux/slab.h>


#define DEBUG_CONFIG 0
#if DEBUG_CONFIG
# define DBGC(args)     printk args
#else
# define DBGC(args)
#endif

#define ROUND_UP(x, a)		(((x) + (a) - 1) & ~((a) - 1))

static int __init
pbus_assign_resources_sorted(struct pci_bus *bus,
			     struct pbus_set_ranges_data *ranges)
{
	struct list_head *ln;
	struct resource *res;
	struct resource_list head_io, head_mem, *list, *tmp;
	unsigned long io_reserved = 0, mem_reserved = 0;
	int idx, found_vga = 0;

	head_io.next = head_mem.next = NULL;
	for (ln=bus->devices.next; ln != &bus->devices; ln=ln->next) {
		struct pci_dev *dev = pci_dev_b(ln);
		u16 class = dev->class >> 8;
		u16 cmd;

		/* First, disable the device to avoid side
		   effects of possibly overlapping I/O and
		   memory ranges.
		   Leave VGA enabled - for obvious reason. :-)
		   Same with all sorts of bridges - they may
		   have VGA behind them.  */
		if (class == PCI_CLASS_DISPLAY_VGA
				|| class == PCI_CLASS_NOT_DEFINED_VGA)
			found_vga = 1;
		else if (class >> 8 != PCI_BASE_CLASS_BRIDGE) {
			pci_read_config_word(dev, PCI_COMMAND, &cmd);
			cmd &= ~(PCI_COMMAND_IO | PCI_COMMAND_MEMORY
						| PCI_COMMAND_MASTER);
			pci_write_config_word(dev, PCI_COMMAND, cmd);
		}

		/* Reserve some resources for CardBus.
		   Are these values reasonable? */
		if (class == PCI_CLASS_BRIDGE_CARDBUS) {
			io_reserved += 8*1024;
			mem_reserved += 32*1024*1024;
			continue;
		}

		pdev_sort_resources(dev, &head_io, IORESOURCE_IO);
		pdev_sort_resources(dev, &head_mem, IORESOURCE_MEM);
	}

	for (list = head_io.next; list;) {
		res = list->res;
		idx = res - &list->dev->resource[0];
		if (pci_assign_resource(list->dev, idx) == 0
		    && ranges->io_end < res->end)
			ranges->io_end = res->end;
		tmp = list;
		list = list->next;
		kfree(tmp);
	}
	for (list = head_mem.next; list;) {
		res = list->res;
		idx = res - &list->dev->resource[0];
		if (pci_assign_resource(list->dev, idx) == 0
		    && ranges->mem_end < res->end)
			ranges->mem_end = res->end;
		tmp = list;
		list = list->next;
		kfree(tmp);
	}

	ranges->io_end += io_reserved;
	ranges->mem_end += mem_reserved;

	/* PCI-to-PCI Bridge Architecture Specification rev. 1.1 (1998)
	   requires that if there is no I/O ports or memory behind the
	   bridge, corresponding range must be turned off by writing base
	   value greater than limit to the bridge's base/limit registers.  */
#if 1
	/* But assuming that some hardware designed before 1998 might
	   not support this (very unlikely - at least all DEC bridges
	   are ok and I believe that was standard de-facto. -ink), we
	   must allow for at least one unit.  */
	if (ranges->io_end == ranges->io_start)
		ranges->io_end += 1;
	if (ranges->mem_end == ranges->mem_start)
		ranges->mem_end += 1;
#endif
	ranges->io_end = ROUND_UP(ranges->io_end, 4*1024);
	ranges->mem_end = ROUND_UP(ranges->mem_end, 1024*1024);

	return found_vga;
}

/* Initialize bridges with base/limit values we have collected */
static void __init
pci_setup_bridge(struct pci_bus *bus)
{
	struct pbus_set_ranges_data ranges;
	struct pci_dev *bridge = bus->self;
	u32 l;

	if (!bridge || (bridge->class >> 8) != PCI_CLASS_BRIDGE_PCI)
		return;
	ranges.io_start = bus->resource[0]->start;
	ranges.io_end = bus->resource[0]->end;
	ranges.mem_start = bus->resource[1]->start;
	ranges.mem_end = bus->resource[1]->end;
	pcibios_fixup_pbus_ranges(bus, &ranges);

	DBGC((KERN_ERR "PCI: Bus %d, bridge: %s\n", bus->number, bridge->name));
	DBGC((KERN_ERR "  IO window: %04lx-%04lx\n", ranges.io_start, ranges.io_end));
	DBGC((KERN_ERR "  MEM window: %08lx-%08lx\n", ranges.mem_start, ranges.mem_end));

	/* Set up the top and bottom of the PCI I/O segment for this bus. */
	pci_read_config_dword(bridge, PCI_IO_BASE, &l);
	l &= 0xffff0000;
	l |= (ranges.io_start >> 8) & 0x00f0;
	l |= ranges.io_end & 0xf000;
	pci_write_config_dword(bridge, PCI_IO_BASE, l);

	/* Clear upper 16 bits of I/O base/limit. */
	pci_write_config_dword(bridge, PCI_IO_BASE_UPPER16, 0);

	/* Clear out the upper 32 bits of PREF base/limit. */
	pci_write_config_dword(bridge, PCI_PREF_BASE_UPPER32, 0);
	pci_write_config_dword(bridge, PCI_PREF_LIMIT_UPPER32, 0);

	/* Set up the top and bottom of the PCI Memory segment
	   for this bus. */
	l = (ranges.mem_start >> 16) & 0xfff0;
	l |= ranges.mem_end & 0xfff00000;
	pci_write_config_dword(bridge, PCI_MEMORY_BASE, l);

	/* Set up PREF base/limit. */
	l = (bus->resource[2]->start >> 16) & 0xfff0;
	l |= bus->resource[2]->end & 0xfff00000;
	pci_write_config_dword(bridge, PCI_PREF_MEMORY_BASE, l);

	/* Check if we have VGA behind the bridge.
	   Enable ISA in either case. */
	l = (bus->resource[0]->flags & IORESOURCE_BUS_HAS_VGA) ? 0x0c : 0x04;
	pci_write_config_word(bridge, PCI_BRIDGE_CONTROL, l);
}

static void __init
pbus_assign_resources(struct pci_bus *bus, struct pbus_set_ranges_data *ranges)
{
	struct list_head *ln;
	int found_vga = pbus_assign_resources_sorted(bus, ranges);

	if (!ranges->found_vga && found_vga) {
		struct pci_bus *b;

		ranges->found_vga = 1;
		/* Propogate presence of the VGA to upstream bridges */
		for (b = bus; b->parent; b = b->parent) {
#if 0
			/* ? Do we actually need to enable PF memory? */
			b->resource[2]->start = 0;
#endif
			b->resource[0]->flags |= IORESOURCE_BUS_HAS_VGA;
		}
	}
	for (ln=bus->children.next; ln != &bus->children; ln=ln->next) {
		struct pci_bus *b = pci_bus_b(ln);

		b->resource[0]->start = ranges->io_start = ranges->io_end;
		b->resource[1]->start = ranges->mem_start = ranges->mem_end;

		pbus_assign_resources(b, ranges);

		b->resource[0]->end = ranges->io_end - 1;
		b->resource[1]->end = ranges->mem_end - 1;

		pci_setup_bridge(b);
	}
}

void __init
pci_assign_unassigned_resources(void)
{
	struct pbus_set_ranges_data ranges;
	struct list_head *ln;
	struct pci_dev *dev;

	for(ln=pci_root_buses.next; ln != &pci_root_buses; ln=ln->next) {
		struct pci_bus *b = pci_bus_b(ln);

		ranges.io_start = b->resource[0]->start + PCIBIOS_MIN_IO;
		ranges.mem_start = b->resource[1]->start + PCIBIOS_MIN_MEM;
		ranges.io_end = ranges.io_start;
		ranges.mem_end = ranges.mem_start;
		ranges.found_vga = 0;
		pbus_assign_resources(b, &ranges);
	}
	pci_for_each_dev(dev) {
		pdev_enable_device(dev);
	}
}

/* Check whether the bridge supports I/O forwarding.
   If not, its I/O base/limit register must be
   read-only and read as 0. */
unsigned long __init
pci_bridge_check_io(struct pci_dev *bridge)
{
	u16 io;

	pci_read_config_word(bridge, PCI_IO_BASE, &io);
	if (!io) {
		pci_write_config_word(bridge, PCI_IO_BASE, 0xf0f0);
		pci_read_config_word(bridge, PCI_IO_BASE, &io);
		pci_write_config_word(bridge, PCI_IO_BASE, 0x0);
	}
	if (io)
		return IORESOURCE_IO;
	printk(KERN_WARNING "PCI: bridge %s does not support I/O forwarding!\n",
				bridge->name);
	return 0;
}
