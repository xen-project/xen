/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2004 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: phys_dev.c
 *      Author: Rolf Neugebauer (rolf.neugebauer@intel.com)
 *        Date: Mar 2004
 *
 * Description: XenoLinux wrappers for PCI interrupt handling.
 *              very simple since someone else is doing all the hard bits
 */


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
#include <linux/interrupt.h>
#include <linux/irq.h>

#include "pci-i386.h"

#include <asm/hypervisor-ifs/physdev.h>

unsigned int pcibios_irq_mask = 0xfff8;

void eisa_set_level_irq(unsigned int irq)
{
    /* dummy */
}

void __init pcibios_irq_init(void)
{
	printk("PCI: IRQ init\n");
}

void __init pcibios_fixup_irqs(void)
{
	struct pci_dev *dev;
    physdev_op_t op;
	int ret;


	printk("PCI: IRQ fixup\n");
	pci_for_each_dev(dev) {

        op.cmd  = PHYSDEVOP_FIND_IRQ;
        op.u.find_irq.seg  = 0;
        op.u.find_irq.bus  = dev->bus->number;
        op.u.find_irq.dev  = PCI_SLOT(dev->devfn);
        op.u.find_irq.func = PCI_FUNC(dev->devfn);

        if ( (ret = HYPERVISOR_physdev_op(&op)) != 0 )
        {
            printk(KERN_ALERT "pci find irq error\n");
            return;
        }

        dev->irq = op.u.find_irq.irq;
        printk(KERN_INFO "PCI IRQ: [%02x:%02x:%02x] -> %d\n",
               dev->bus->number, PCI_SLOT(dev->devfn),
               PCI_FUNC(dev->devfn), dev->irq);
    }
    return;
}

void pcibios_penalize_isa_irq(int irq)
{
    /* dummy */
}

void pcibios_enable_irq(struct pci_dev *dev)
{
	u8 pin;
	
	pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &pin);

	if (pin  && !dev->irq) {
		printk(KERN_WARNING "PCI: No IRQ known for interrupt pin %c of "
               "device %s.\n", 'A' + pin - 1, dev->slot_name);
	}
}
