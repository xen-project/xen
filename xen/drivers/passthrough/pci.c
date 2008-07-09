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
#include <xen/pci_regs.h>
#include <xen/list.h>
#include <xen/prefetch.h>
#include <xen/iommu.h>
#include <xen/delay.h>
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

int pci_add_device(u8 bus, u8 devfn)
{
    struct pci_dev *pdev;
    int ret = -ENOMEM;

    write_lock(&pcidevs_lock);
    pdev = alloc_pdev(bus, devfn);
    if ( !pdev )
	goto out;

    ret = 0;
    spin_lock(&pdev->lock);
    if ( !pdev->domain )
    {
	pdev->domain = dom0;
	list_add(&pdev->domain_list, &dom0->arch.pdev_list);
	ret = iommu_add_device(pdev);
    }
    spin_unlock(&pdev->lock);
    printk(XENLOG_DEBUG "PCI add device %02x:%02x.%x\n", bus,
	   PCI_SLOT(devfn), PCI_FUNC(devfn));

out:
    write_unlock(&pcidevs_lock);
    return ret;
}

int pci_remove_device(u8 bus, u8 devfn)
{
    struct pci_dev *pdev;
    int ret = -ENODEV;;

    write_lock(&pcidevs_lock);
    list_for_each_entry ( pdev, &alldevs_list, alldevs_list )
        if ( pdev->bus == bus && pdev->devfn == devfn )
	{
	    spin_lock(&pdev->lock);
	    ret = iommu_remove_device(pdev);
	    if ( pdev->domain )
		list_del(&pdev->domain_list);
	    pci_cleanup_msi(pdev);
	    free_pdev(pdev);
	    printk(XENLOG_DEBUG "PCI remove device %02x:%02x.%x\n", bus,
		   PCI_SLOT(devfn), PCI_FUNC(devfn));
	    break;
	}

    write_unlock(&pcidevs_lock);
    return ret;
}

void pci_release_devices(struct domain *d)
{
    struct pci_dev *pdev;
    u8 bus, devfn;

    while ( (pdev = pci_lock_domain_pdev(d, -1, -1)) )
    {
        pci_cleanup_msi(pdev);
        bus = pdev->bus; devfn = pdev->devfn;
        spin_unlock(&pdev->lock);
        deassign_device(d, bus, devfn);
    }
}

#define PCI_D3hot	        (3)
#define PCI_CONFIG_DWORD_SIZE   (64)
#define PCI_EXP_DEVCAP_FLR      (1 << 28)
#define PCI_EXP_DEVCTL_FLR      (1 << 15)

void pdev_flr(struct pci_dev *pdev)
{
    u8 pos;
    u32 dev_cap, dev_status, pm_ctl;
    int flr = 0;
    u8 dev = PCI_SLOT(pdev->devfn);
    u8 func = PCI_FUNC(pdev->devfn);

    pos = pci_find_cap_offset(pdev->bus, dev, func, PCI_CAP_ID_EXP);
    if ( pos != 0 )
    {
        dev_cap = pci_conf_read32(pdev->bus, dev, func, pos + PCI_EXP_DEVCAP);
        if ( dev_cap & PCI_EXP_DEVCAP_FLR )
        {
            pci_conf_write32(pdev->bus, dev, func,
                             pos + PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_FLR);
            do {
                dev_status = pci_conf_read32(pdev->bus, dev, func,
                                             pos + PCI_EXP_DEVSTA);
            } while ( dev_status & PCI_EXP_DEVSTA_TRPND );

            flr = 1;
        }
    }

    /* If this device doesn't support function level reset,
     * program device from D0 t0 D3hot, and then return to D0
     * to implement function level reset
     */
    if ( flr == 0 )
    {
        pos = pci_find_cap_offset(pdev->bus, dev, func, PCI_CAP_ID_PM);
        if ( pos != 0 )
        {
            int i;
            u32 config[PCI_CONFIG_DWORD_SIZE];
            for ( i = 0; i < PCI_CONFIG_DWORD_SIZE; i++ )
                config[i] = pci_conf_read32(pdev->bus, dev, func, i*4);

            /* Enter D3hot without soft reset */
            pm_ctl = pci_conf_read32(pdev->bus, dev, func, pos + PCI_PM_CTRL);
            pm_ctl |= PCI_PM_CTRL_NO_SOFT_RESET;
            pm_ctl &= ~PCI_PM_CTRL_STATE_MASK;
            pm_ctl |= PCI_D3hot;
            pci_conf_write32(pdev->bus, dev, func, pos + PCI_PM_CTRL, pm_ctl);
            mdelay(10);

            /* From D3hot to D0 */
            pci_conf_write32(pdev->bus, dev, func, pos + PCI_PM_CTRL, 0);
            mdelay(10);

            /* Write saved configurations to device */
            for ( i = 0; i < PCI_CONFIG_DWORD_SIZE; i++ )
                pci_conf_write32(pdev->bus, dev, func, i*4, config[i]);

            flr = 1;
        }
    }
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
    register_keyhandler('Q', dump_pci_devices, "dump PCI devices");
    return 0;
}
__initcall(setup_dump_pcidevs);



/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
