/******************************************************************************
 * evtchn-pci.c
 * xen event channel fake PCI device driver
 * Copyright (C) 2005, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <asm/hypervisor.h>
#include <asm/pgtable.h>
#include <xen/interface/memory.h>
#include <xen/features.h>
#ifdef __ia64__
#include <asm/xen/xencomm.h>
#endif

#include "platform-pci.h"

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

#define DRV_NAME    "xen-platform-pci"
#define DRV_VERSION "0.10"
#define DRV_RELDATE "03/03/2005"

char *hypercall_stubs;
EXPORT_SYMBOL(hypercall_stubs);

// Used to be xiaofeng.ling@intel.com
MODULE_AUTHOR("ssmith@xensource.com");
MODULE_DESCRIPTION("Xen platform PCI device");
MODULE_LICENSE("GPL");

unsigned long *phys_to_machine_mapping;
EXPORT_SYMBOL(phys_to_machine_mapping);

static int __devinit init_xen_info(void)
{
	unsigned long shared_info_frame;
	struct xen_add_to_physmap xatp;
	extern void *shared_info_area;

#ifdef __ia64__
	xencomm_init();
#endif

	setup_xen_features();

	shared_info_frame = alloc_xen_mmio(PAGE_SIZE) >> PAGE_SHIFT;
	xatp.domid = DOMID_SELF;
	xatp.idx = 0;
	xatp.space = XENMAPSPACE_shared_info;
	xatp.gpfn = shared_info_frame;
	if (HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp))
		BUG();

	shared_info_area =
		ioremap(shared_info_frame << PAGE_SHIFT, PAGE_SIZE);
	if (shared_info_area == NULL)
		panic("can't map shared info\n");

	phys_to_machine_mapping = NULL;

	gnttab_init();

	return 0;
}

static void __devexit platform_pci_remove(struct pci_dev *pdev)
{
	long ioaddr, iolen;
	long mmio_addr, mmio_len;

	ioaddr = pci_resource_start(pdev, 0);
	iolen = pci_resource_len(pdev, 0);
	mmio_addr = pci_resource_start(pdev, 1);
	mmio_len = pci_resource_len(pdev, 1);

	release_region(ioaddr, iolen);
	release_mem_region(mmio_addr, mmio_len);

	pci_set_drvdata(pdev, NULL);
	free_irq(pdev->irq, pdev);
}

static unsigned long platform_mmio;
static unsigned long platform_mmio_alloc;
static unsigned long platform_mmiolen;

unsigned long alloc_xen_mmio(unsigned long len)
{
	unsigned long addr;

	addr = platform_mmio + platform_mmio_alloc;
	platform_mmio_alloc += len;
	BUG_ON(platform_mmio_alloc > platform_mmiolen);

	return addr;
}

#ifndef __ia64__
/* Lifted from hvmloader.c */
static int get_hypercall_stubs(void)
{
	uint32_t eax, ebx, ecx, edx, pages, msr, i;
	char signature[13];

	cpuid(0x40000000, &eax, &ebx, &ecx, &edx);
	*(uint32_t*)(signature + 0) = ebx;
	*(uint32_t*)(signature + 4) = ecx;
	*(uint32_t*)(signature + 8) = edx;
	signature[12] = 0;

	if (strcmp("XenVMMXenVMM", signature) || (eax < 0x40000002)) {
		printk(KERN_WARNING
		       "Detected Xen platform device but not Xen VMM?"
		       " (sig %s, eax %x)\n",
		       signature, eax);
		return -EINVAL;
	}

	cpuid(0x40000001, &eax, &ebx, &ecx, &edx);

	printk(KERN_INFO "Xen version %d.%d.\n", eax >> 16, eax & 0xffff);

	cpuid(0x40000002, &pages, &msr, &ecx, &edx);

	printk(KERN_INFO "Hypercall area is %u pages.\n", pages);

	/* Use __vmalloc() because vmalloc_exec() is not an exported symbol. */
	/* PAGE_KERNEL_EXEC also is not exported, hence we use PAGE_KERNEL. */
	/* hypercall_stubs = vmalloc_exec(pages * PAGE_SIZE); */
	hypercall_stubs = __vmalloc(pages * PAGE_SIZE,
				    GFP_KERNEL | __GFP_HIGHMEM,
				    __pgprot(__PAGE_KERNEL & ~_PAGE_NX));
	if (hypercall_stubs == NULL)
		return -ENOMEM;

	for (i = 0; i < pages; i++) {
		unsigned long pfn;
		pfn = vmalloc_to_pfn((char *)hypercall_stubs + i*PAGE_SIZE);
		wrmsrl(msr, ((u64)pfn << PAGE_SHIFT) + i);
	}

	return 0;
}
#else /* __ia64__ */
#define get_hypercall_stubs()	(0)
#endif

static uint64_t get_callback_via(struct pci_dev *pdev)
{
	u8 pin;
	int irq;

#ifdef __ia64__
	for (irq = 0; irq < 16; irq++) {
		if (isa_irq_to_vector(irq) == pdev->irq)
			return irq; /* ISA IRQ */
	}
#else /* !__ia64__ */
	irq = pdev->irq;
	if (irq < 16)
		return irq; /* ISA IRQ */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
	pin = pdev->pin;
#else
	pci_read_config_byte(pdev, PCI_INTERRUPT_PIN, &pin);
#endif

	/* We don't know the GSI. Specify the PCI INTx line instead. */
	return (((uint64_t)0x01 << 56) | /* PCI INTx identifier */
		((uint64_t)pci_domain_nr(pdev->bus) << 32) |
		((uint64_t)pdev->bus->number << 16) |
		((uint64_t)(pdev->devfn & 0xff) << 8) |
		((uint64_t)(pin - 1) & 3));
}

/* Invalidate foreign mappings (e.g., in qemu-based device model). */
static uint16_t invlmap_port;
void xen_invalidate_foreign_mappings(void)
{
	outb(0, invlmap_port);
}
EXPORT_SYMBOL(xen_invalidate_foreign_mappings);

static int __devinit platform_pci_init(struct pci_dev *pdev,
				       const struct pci_device_id *ent)
{
	int i, ret;
	long ioaddr, iolen;
	long mmio_addr, mmio_len;
	uint64_t callback_via;

	i = pci_enable_device(pdev);
	if (i)
		return i;

	ioaddr = pci_resource_start(pdev, 0);
	iolen = pci_resource_len(pdev, 0);

	mmio_addr = pci_resource_start(pdev, 1);
	mmio_len = pci_resource_len(pdev, 1);

	callback_via = get_callback_via(pdev);

	if (mmio_addr == 0 || ioaddr == 0 || callback_via == 0) {
		printk(KERN_WARNING DRV_NAME ":no resources found\n");
		return -ENOENT;
	}

	invlmap_port = ioaddr;

	if (request_mem_region(mmio_addr, mmio_len, DRV_NAME) == NULL)
	{
		printk(KERN_ERR ":MEM I/O resource 0x%lx @ 0x%lx busy\n",
		       mmio_addr, mmio_len);
		return -EBUSY;
	}

	if (request_region(ioaddr, iolen, DRV_NAME) == NULL)
	{
		printk(KERN_ERR DRV_NAME ":I/O resource 0x%lx @ 0x%lx busy\n",
		       iolen, ioaddr);
		release_mem_region(mmio_addr, mmio_len);
		return -EBUSY;
	}

	platform_mmio = mmio_addr;
	platform_mmiolen = mmio_len;

	ret = get_hypercall_stubs();
	if (ret < 0)
		goto out;

	if ((ret = init_xen_info()))
		goto out;

	if ((ret = request_irq(pdev->irq, evtchn_interrupt,
			       SA_SHIRQ | SA_SAMPLE_RANDOM,
			       "xen-platform-pci", pdev)))
		goto out;

	if ((ret = set_callback_via(callback_via)))
		goto out;

 out:
	if (ret) {
		release_mem_region(mmio_addr, mmio_len);
		release_region(ioaddr, iolen);
	}

	return ret;
}

#define XEN_PLATFORM_VENDOR_ID 0x5853
#define XEN_PLATFORM_DEVICE_ID 0x0001
static struct pci_device_id platform_pci_tbl[] __devinitdata = {
	{XEN_PLATFORM_VENDOR_ID, XEN_PLATFORM_DEVICE_ID,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	/* Continue to recognise the old ID for now */
	{0xfffd, 0x0101, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0,}
};

MODULE_DEVICE_TABLE(pci, platform_pci_tbl);

static struct pci_driver platform_driver = {
	name:     DRV_NAME,
	probe:    platform_pci_init,
	remove:   __devexit_p(platform_pci_remove),
	id_table: platform_pci_tbl,
};

static int pci_device_registered;

static int __init platform_pci_module_init(void)
{
	int rc;

	rc = pci_module_init(&platform_driver);
	if (rc)
		printk(KERN_INFO DRV_NAME ":No platform pci device model found\n");
	else
		pci_device_registered = 1;

	return rc;
}

static void __exit platform_pci_module_cleanup(void)
{
	printk(KERN_INFO DRV_NAME ":Do platform module cleanup\n");
	/* disable hypervisor for callback irq */
	set_callback_via(0);
	if (pci_device_registered)
		pci_unregister_driver(&platform_driver);
}

module_init(platform_pci_module_init);
module_exit(platform_pci_module_cleanup);
