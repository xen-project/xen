/*
 * Copyright (C) 2008,  Netronome Systems, Inc.
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
 */

#include <xen/sched.h>
#include <xen/pci.h>
#include <xen/list.h>
#include <xen/prefetch.h>
#include <xen/keyhandler.h>


LIST_HEAD(alldevs_list);
rwlock_t pcidevs_lock = RW_LOCK_UNLOCKED;

struct pci_dev *alloc_pdev(u8 bus, u8 devfn)
{
    struct pci_dev *pdev;

    list_for_each_entry ( pdev, &alldevs_list, alldevs_list )
        if ( pdev->bus == bus && pdev->devfn == devfn )
	    return pdev;

    pdev = xmalloc(struct pci_dev);
    if ( !pdev )
	return NULL;

    *((u8*) &pdev->bus) = bus;
    *((u8*) &pdev->devfn) = devfn;
    pdev->domain = NULL;
    spin_lock_init(&pdev->lock);
    INIT_LIST_HEAD(&pdev->msi_list);
    list_add(&pdev->alldevs_list, &alldevs_list);

    return pdev;
}

void free_pdev(struct pci_dev *pdev)
{
    list_del(&pdev->alldevs_list);
    xfree(pdev);
}

struct pci_dev *pci_lock_pdev(int bus, int devfn)
{
    struct pci_dev *pdev;

    read_lock(&pcidevs_lock);
    list_for_each_entry ( pdev, &alldevs_list, alldevs_list )
        if ( (pdev->bus == bus || bus == -1) &&
	     (pdev->devfn == devfn || devfn == -1) )
	{
	    spin_lock(&pdev->lock);
	    read_unlock(&pcidevs_lock);
	    return pdev;
	}
    read_unlock(&pcidevs_lock);

    return NULL;
}

struct pci_dev *pci_lock_domain_pdev(struct domain *d, int bus, int devfn)
{
    struct pci_dev *pdev;

    read_lock(&pcidevs_lock);
    list_for_each_entry ( pdev, &d->arch.pdev_list, domain_list )
    {
	spin_lock(&pdev->lock);
        if ( (pdev->bus == bus || bus == -1) &&
	     (pdev->devfn == devfn || devfn == -1) &&
	     (pdev->domain == d) )
	{
	    read_unlock(&pcidevs_lock);
	    return pdev;
	}
	spin_unlock(&pdev->lock);
    }
    read_unlock(&pcidevs_lock);

    return NULL;
}

static void dump_pci_devices(unsigned char ch)
{
    struct pci_dev *pdev;
    struct msi_desc *msi;

    printk("==== PCI devices ====\n");
    read_lock(&pcidevs_lock);

    list_for_each_entry ( pdev, &alldevs_list, alldevs_list )
    {
	spin_lock(&pdev->lock);
        printk("%02x:%02x.%x - dom %-3d - MSIs < ",
               pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn),
               pdev->domain ? pdev->domain->domain_id : -1);
	list_for_each_entry ( msi, &pdev->msi_list, list )
	    printk("%d ", msi->vector);
	printk(">\n");
	spin_unlock(&pdev->lock);
    }

    read_unlock(&pcidevs_lock);
}

static int __init setup_dump_pcidevs(void)
{
    register_keyhandler('P', dump_pci_devices, "dump PCI devices");
    return 0;
}
__initcall(setup_dump_pcidevs);
