/*
 * direct.c - Low-level direct PCI config space access
 */

#include <linux/pci.h>
#include <linux/init.h>
#include "pci.h"

#include <asm-xen/xen-public/xen.h>
#include <asm-xen/xen-public/physdev.h>

/*
 * Functions for accessing PCI configuration space with type xen accesses
 */

static int pci_conf_read (int seg, int bus, int devfn, int reg, int len, u32 *value)
{
	unsigned long flags;
	physdev_op_t op;
	int ret;

	if (!value || (bus > 255) || (devfn > 255) || (reg > 255))
		return -EINVAL;

	spin_lock_irqsave(&pci_config_lock, flags);

	op.cmd = PHYSDEVOP_PCI_CFGREG_READ;
	op.u.pci_cfgreg_read.bus  = bus;
	op.u.pci_cfgreg_read.dev  = (devfn & ~0x7) >> 3;
	op.u.pci_cfgreg_read.func = devfn & 0x7;
	op.u.pci_cfgreg_read.reg  = reg;
	op.u.pci_cfgreg_read.len  = len;

	ret = HYPERVISOR_physdev_op(&op);
	if (ret == 0)
		*value = op.u.pci_cfgreg_read.value;

	spin_unlock_irqrestore(&pci_config_lock, flags);

	return ret;
}

static int pci_conf_write (int seg, int bus, int devfn, int reg, int len, u32 value)
{
	unsigned long flags;
	physdev_op_t op;
	int ret;

	if ((bus > 255) || (devfn > 255) || (reg > 255)) 
		return -EINVAL;

	spin_lock_irqsave(&pci_config_lock, flags);

	op.cmd = PHYSDEVOP_PCI_CFGREG_WRITE;
	op.u.pci_cfgreg_write.bus   = bus;
	op.u.pci_cfgreg_write.dev   = (devfn & ~0x7) >> 3;
	op.u.pci_cfgreg_write.func  = devfn & 0x7;
	op.u.pci_cfgreg_write.reg   = reg;
	op.u.pci_cfgreg_write.len   = len;
	op.u.pci_cfgreg_write.value = value;

	ret = HYPERVISOR_physdev_op(&op);

	spin_unlock_irqrestore(&pci_config_lock, flags);

	return ret;
}

struct pci_raw_ops pci_direct_xen = {
	.read =		pci_conf_read,
	.write =	pci_conf_write,
};


static int __init pci_direct_init(void)
{

        printk(KERN_INFO "PCI: Using configuration type Xen\n");
        raw_pci_ops = &pci_direct_xen;
        return 0;
}

arch_initcall(pci_direct_init);
