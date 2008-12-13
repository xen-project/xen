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
#include <asm/hvm/iommu.h>
#include <asm/hvm/irq.h>
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
    memset(pdev, 0, sizeof(struct pci_dev));

    *((u8*) &pdev->bus) = bus;
    *((u8*) &pdev->devfn) = devfn;
    pdev->domain = NULL;
    INIT_LIST_HEAD(&pdev->msi_list);
    list_add(&pdev->alldevs_list, &alldevs_list);

    return pdev;
}

void free_pdev(struct pci_dev *pdev)
{
    list_del(&pdev->alldevs_list);
    xfree(pdev);
}

struct pci_dev *pci_get_pdev(int bus, int devfn)
{
    struct pci_dev *pdev = NULL;

    ASSERT(rw_is_locked(&pcidevs_lock));

    list_for_each_entry ( pdev, &alldevs_list, alldevs_list )
        if ( (pdev->bus == bus || bus == -1) &&
             (pdev->devfn == devfn || devfn == -1) )
        {
            return pdev;
        }

    return NULL;
}

struct pci_dev *pci_get_pdev_by_domain(struct domain *d, int bus, int devfn)
{
    struct pci_dev *pdev = NULL;

    ASSERT(rw_is_locked(&pcidevs_lock));

    list_for_each_entry ( pdev, &alldevs_list, alldevs_list )
         if ( (pdev->bus == bus || bus == -1) &&
              (pdev->devfn == devfn || devfn == -1) &&
              (pdev->domain == d) )
         {
             return pdev;
         }

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
    if ( !pdev->domain )
    {
        pdev->domain = dom0;
        ret = iommu_add_device(pdev);
        if ( ret )
            goto out;

        list_add(&pdev->domain_list, &dom0->arch.pdev_list);
    }

out:
    write_unlock(&pcidevs_lock);
    printk(XENLOG_DEBUG "PCI add device %02x:%02x.%x\n", bus,
           PCI_SLOT(devfn), PCI_FUNC(devfn));
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

static void pci_clean_dpci_irqs(struct domain *d)
{
    struct hvm_irq_dpci *hvm_irq_dpci = NULL;
    uint32_t i;
    struct list_head *digl_list, *tmp;
    struct dev_intx_gsi_link *digl;

    if ( !iommu_enabled )
        return;

    if ( !is_hvm_domain(d) && !need_iommu(d) )
        return;

    spin_lock(&d->event_lock);
    hvm_irq_dpci = domain_get_irq_dpci(d);
    if ( hvm_irq_dpci != NULL )
    {
        for ( i = find_first_bit(hvm_irq_dpci->mapping, NR_IRQS);
              i < NR_IRQS;
              i = find_next_bit(hvm_irq_dpci->mapping, NR_IRQS, i + 1) )
        {
            pirq_guest_unbind(d, i);
            kill_timer(&hvm_irq_dpci->hvm_timer[irq_to_vector(i)]);

            list_for_each_safe ( digl_list, tmp,
                                 &hvm_irq_dpci->mirq[i].digl_list )
            {
                digl = list_entry(digl_list,
                                  struct dev_intx_gsi_link, list);
                list_del(&digl->list);
                xfree(digl);
            }
        }

        d->arch.hvm_domain.irq.dpci = NULL;
        xfree(hvm_irq_dpci);
    }
    spin_unlock(&d->event_lock);
}

void pci_release_devices(struct domain *d)
{
    struct pci_dev *pdev;
    u8 bus, devfn;

    read_lock(&pcidevs_lock);
    pci_clean_dpci_irqs(d);
    while ( (pdev = pci_get_pdev_by_domain(d, -1, -1)) )
    {
        pci_cleanup_msi(pdev);
        bus = pdev->bus; devfn = pdev->devfn;
        deassign_device(d, bus, devfn);
    }
    read_unlock(&pcidevs_lock);
}

#ifdef SUPPORT_MSI_REMAPPING
static void dump_pci_devices(unsigned char ch)
{
    struct pci_dev *pdev;
    struct msi_desc *msi;

    printk("==== PCI devices ====\n");
    read_lock(&pcidevs_lock);

    list_for_each_entry ( pdev, &alldevs_list, alldevs_list )
    {
        printk("%02x:%02x.%x - dom %-3d - MSIs < ",
               pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn),
               pdev->domain ? pdev->domain->domain_id : -1);
        list_for_each_entry ( msi, &pdev->msi_list, list )
               printk("%d ", msi->vector);
        printk(">\n");
    }

    read_unlock(&pcidevs_lock);
}

static int __init setup_dump_pcidevs(void)
{
    register_keyhandler('Q', dump_pci_devices, "dump PCI devices");
    return 0;
}
__initcall(setup_dump_pcidevs);
#endif


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
