/*
 * PCI Frontend Stub - puts some "dummy" functions in to the Linux x86 PCI core
 *                     to support the Xen PCI Frontend's operation
 *
 *   Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <asm/acpi.h>
#include "pci.h"

static int pcifront_enable_irq(struct pci_dev *dev)
{
	u8 irq;
	pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &irq);
	dev->irq = irq;

	return 0;
}

extern u8 pci_cache_line_size;

static int __init pcifront_x86_stub_init(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	/* Only install our method if we haven't found real hardware already */
	if (raw_pci_ops)
		return 0;

	printk(KERN_INFO "PCI: setting up Xen PCI frontend stub\n");

	/* Copied from arch/i386/pci/common.c */
	pci_cache_line_size = 32 >> 2;
	if (c->x86 >= 6 && c->x86_vendor == X86_VENDOR_AMD)
		pci_cache_line_size = 64 >> 2;	/* K7 & K8 */
	else if (c->x86 > 6 && c->x86_vendor == X86_VENDOR_INTEL)
		pci_cache_line_size = 128 >> 2;	/* P4 */

	/* On x86, we need to disable the normal IRQ routing table and
	 * just ask the backend
	 */
	pcibios_enable_irq = pcifront_enable_irq;
	pcibios_disable_irq = NULL;

#ifdef CONFIG_ACPI
	/* Keep ACPI out of the picture */
	acpi_noirq = 1;
#endif

	return 0;
}

arch_initcall(pcifront_x86_stub_init);
