/*
 *	Low-Level PCI Support for PC -- Routing of Interrupts
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/io_apic.h>
#include <asm/hw_irq.h>
#include <linux/acpi.h>

#include "pci.h"

#include <asm-xen/xen-public/xen.h>
#include <asm-xen/xen-public/physdev.h>

static int pirq_enable_irq(struct pci_dev *dev);

/*
 * Never use: 0, 1, 2 (timer, keyboard, and cascade)
 * Avoid using: 13, 14 and 15 (FP error and IDE).
 * Penalize: 3, 4, 6, 7, 12 (known ISA uses: serial, floppy, parallel and mouse)
 */
unsigned int pcibios_irq_mask = 0xfff8;

static int pirq_penalty[16] = {
	1000000, 1000000, 1000000, 1000, 1000, 0, 1000, 1000,
	0, 0, 0, 0, 1000, 100000, 100000, 100000
};

int (*pcibios_enable_irq)(struct pci_dev *dev) = NULL;


static int __init pcibios_irq_init(void)
{
	int bus;
	physdev_op_t op;

	DBG("PCI: IRQ init\n");

	if (pcibios_enable_irq || raw_pci_ops == NULL)
		return 0;

	op.cmd = PHYSDEVOP_PCI_PROBE_ROOT_BUSES;
	if (HYPERVISOR_physdev_op(&op) != 0) {
		printk(KERN_WARNING "PCI: System does not support PCI\n");
		return 0;
	}

	printk(KERN_INFO "PCI: Probing PCI hardware\n");
	for (bus = 0; bus < 256; bus++)
		if (test_bit(bus, (unsigned long *)
			&op.u.pci_probe_root_buses.busmask[0]))
			(void)pcibios_scan_root(bus);

	pcibios_enable_irq = pirq_enable_irq;

	return 0;
}

subsys_initcall(pcibios_irq_init);


static void pirq_penalize_isa_irq(int irq)
{
	/*
	 *  If any ISAPnP device reports an IRQ in its list of possible
	 *  IRQ's, we try to avoid assigning it to PCI devices.
	 */
	if (irq < 16)
		pirq_penalty[irq] += 100;
}

void pcibios_penalize_isa_irq(int irq)
{
#ifdef CONFIG_ACPI_PCI
	if (!acpi_noirq)
		acpi_penalize_isa_irq(irq);
	else
#endif
		pirq_penalize_isa_irq(irq);
}

static int pirq_enable_irq(struct pci_dev *dev)
{
	int err;
	u8  pin;
	physdev_op_t op;

	/* Inform Xen that we are going to use this device. */
	op.cmd = PHYSDEVOP_PCI_INITIALISE_DEVICE;
	op.u.pci_initialise_device.bus  = dev->bus->number;
	op.u.pci_initialise_device.dev  = PCI_SLOT(dev->devfn);
	op.u.pci_initialise_device.func = PCI_FUNC(dev->devfn);
	if ( (err = HYPERVISOR_physdev_op(&op)) != 0 )
		return err;

	/* Now we can bind to the very final IRQ line. */
	pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &pin);
	dev->irq = pin;

	/* Sanity-check that an interrupt-producing device is routed
	 * to an IRQ. */
	pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &pin);
	if (pin != 0) {
		if (dev->irq != 0)
			printk(KERN_INFO "PCI: Obtained IRQ %d for device %s\n",
			    dev->irq, dev->slot_name);
		else
			printk(KERN_WARNING "PCI: No IRQ known for interrupt "
			    "pin %c of device %s.\n", 'A' + pin - 1,
			    dev->slot_name);
	}

	return 0;
}

int pci_vector_resources(int last, int nr_released)
{
	int count = nr_released;

	int next = last;
	int offset = (last % 8);

	while (next < FIRST_SYSTEM_VECTOR) {
		next += 8;
#ifdef CONFIG_X86_64
		if (next == IA32_SYSCALL_VECTOR)
			continue;
#else
		if (next == SYSCALL_VECTOR)
			continue;
#endif
		count++;
		if (next >= FIRST_SYSTEM_VECTOR) {
			if (offset%8) {
				next = FIRST_DEVICE_VECTOR + offset;
				offset++;
				continue;
			}
			count--;
		}
	}

	return count;
}
