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
spinlock_t pcidevs_lock = SPIN_LOCK_UNLOCKED;

#define MAX_BUSES 256
static struct {
    u8 map;
    u8 bus;
    u8 devfn;
} bus2bridge[MAX_BUSES];

/* bus2bridge_lock protects bus2bridge array */
static DEFINE_SPINLOCK(bus2bridge_lock);

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
    spin_lock_init(&pdev->msix_table_lock);

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

    ASSERT(spin_is_locked(&pcidevs_lock));

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

    list_for_each_entry ( pdev, &alldevs_list, alldevs_list )
         if ( (pdev->bus == bus || bus == -1) &&
              (pdev->devfn == devfn || devfn == -1) &&
              (pdev->domain == d) )
         {
             return pdev;
         }

    return NULL;
}

/**
 * pci_enable_acs - enable ACS if hardware support it
 * @dev: the PCI device
 */
void pci_enable_acs(struct pci_dev *pdev)
{
    int pos;
    u16 cap;
    u16 ctrl;

    u8 bus = pdev->bus;
    u8 dev = PCI_SLOT(pdev->devfn);
    u8 func = PCI_FUNC(pdev->devfn);

    if ( !iommu_enabled )
        return;

    pos = pci_find_ext_capability(0, bus, pdev->devfn, PCI_EXT_CAP_ID_ACS);
    if (!pos)
        return;

    cap = pci_conf_read16(bus, dev, func, pos + PCI_ACS_CAP);
    ctrl = pci_conf_read16(bus, dev, func, pos + PCI_ACS_CTRL);

    /* Source Validation */
    ctrl |= (cap & PCI_ACS_SV);

    /* P2P Request Redirect */
    ctrl |= (cap & PCI_ACS_RR);

    /* P2P Completion Redirect */
    ctrl |= (cap & PCI_ACS_CR);

    /* Upstream Forwarding */
    ctrl |= (cap & PCI_ACS_UF);

    pci_conf_write16(bus, dev, func, pos + PCI_ACS_CTRL, ctrl);
}

int pci_add_device(u8 bus, u8 devfn)
{
    struct pci_dev *pdev;
    int ret = -ENOMEM;

    spin_lock(&pcidevs_lock);
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
        pci_enable_acs(pdev);
    }

out:
    spin_unlock(&pcidevs_lock);
    printk(XENLOG_DEBUG "PCI add device %02x:%02x.%x\n", bus,
           PCI_SLOT(devfn), PCI_FUNC(devfn));
    return ret;
}

int pci_remove_device(u8 bus, u8 devfn)
{
    struct pci_dev *pdev;
    int ret = -ENODEV;

    spin_lock(&pcidevs_lock);
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

    spin_unlock(&pcidevs_lock);
    return ret;
}

int pci_add_device_ext(u8 bus, u8 devfn, struct pci_dev_info *info)
{
    int ret;
    char *pdev_type;
    struct pci_dev *pdev;

    if (info->is_extfn)
        pdev_type = "Extended Function";
    else if (info->is_virtfn)
        pdev_type = "Virtual Function";
    else
        return -EINVAL;


    ret = -ENOMEM;
    spin_lock(&pcidevs_lock);
    pdev = alloc_pdev(bus, devfn);
    if ( !pdev )
        goto out;

    pdev->info = *info;

    ret = 0;
    if ( !pdev->domain )
    {
        pdev->domain = dom0;
        ret = iommu_add_device(pdev);
        if ( ret )
            goto out;

        list_add(&pdev->domain_list, &dom0->arch.pdev_list);
        pci_enable_acs(pdev);
    }

out:
    spin_unlock(&pcidevs_lock);
    printk(XENLOG_DEBUG "PCI add %s %02x:%02x.%x\n", pdev_type,
           bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

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

    if ( !need_iommu(d) )
        return;

    spin_lock(&d->event_lock);
    hvm_irq_dpci = domain_get_irq_dpci(d);
    if ( hvm_irq_dpci != NULL )
    {
        tasklet_kill(&hvm_irq_dpci->dirq_tasklet);

        for ( i = find_first_bit(hvm_irq_dpci->mapping, d->nr_pirqs);
              i < d->nr_pirqs;
              i = find_next_bit(hvm_irq_dpci->mapping, d->nr_pirqs, i + 1) )
        {
            pirq_guest_unbind(d, i);
            kill_timer(&hvm_irq_dpci->hvm_timer[domain_pirq_to_irq(d, i)]);

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
        free_hvm_irq_dpci(hvm_irq_dpci);
    }
    spin_unlock(&d->event_lock);
}

void pci_release_devices(struct domain *d)
{
    struct pci_dev *pdev;
    u8 bus, devfn;

    spin_lock(&pcidevs_lock);
    pci_clean_dpci_irqs(d);
    while ( (pdev = pci_get_pdev_by_domain(d, -1, -1)) )
    {
        pci_cleanup_msi(pdev);
        bus = pdev->bus; devfn = pdev->devfn;
        if ( deassign_device(d, bus, devfn) )
            printk("domain %d: deassign device (%02x:%02x.%x) failed!\n",
                   d->domain_id, pdev->bus, PCI_SLOT(pdev->devfn),
                   PCI_FUNC(pdev->devfn));
    }
    spin_unlock(&pcidevs_lock);
}

#define PCI_CLASS_BRIDGE_PCI     0x0604

int pdev_type(u8 bus, u8 devfn)
{
    u16 class_device;
    u16 status, creg;
    int pos;
    u8 d = PCI_SLOT(devfn), f = PCI_FUNC(devfn);

    class_device = pci_conf_read16(bus, d, f, PCI_CLASS_DEVICE);
    if ( class_device == PCI_CLASS_BRIDGE_PCI )
    {
        pos = pci_find_next_cap(bus, devfn,
                                PCI_CAPABILITY_LIST, PCI_CAP_ID_EXP);
        if ( !pos )
            return DEV_TYPE_LEGACY_PCI_BRIDGE;
        creg = pci_conf_read16(bus, d, f, pos + PCI_EXP_FLAGS);
        return ((creg & PCI_EXP_FLAGS_TYPE) >> 4) == PCI_EXP_TYPE_PCI_BRIDGE ?
            DEV_TYPE_PCIe2PCI_BRIDGE : DEV_TYPE_PCIe_BRIDGE;
    }

    status = pci_conf_read16(bus, d, f, PCI_STATUS);
    if ( !(status & PCI_STATUS_CAP_LIST) )
        return DEV_TYPE_PCI;

    if ( pci_find_next_cap(bus, devfn, PCI_CAPABILITY_LIST, PCI_CAP_ID_EXP) )
        return DEV_TYPE_PCIe_ENDPOINT;

    return DEV_TYPE_PCI;
}

/*
 * find the upstream PCIe-to-PCI/PCIX bridge or PCI legacy bridge
 * return 0: the device is integrated PCI device or PCIe
 * return 1: find PCIe-to-PCI/PCIX bridge or PCI legacy bridge
 * return -1: fail
 */
int find_upstream_bridge(u8 *bus, u8 *devfn, u8 *secbus)
{
    int ret = 0;
    int cnt = 0;

    if ( *bus == 0 )
        return 0;

    if ( !bus2bridge[*bus].map )
        return 0;

    ret = 1;
    spin_lock(&bus2bridge_lock);
    while ( bus2bridge[*bus].map )
    {
        *secbus = *bus;
        *devfn = bus2bridge[*bus].devfn;
        *bus = bus2bridge[*bus].bus;
        if ( cnt++ >= MAX_BUSES )
        {
            ret = -1;
            goto out;
        }
    }

out:
    spin_unlock(&bus2bridge_lock);
    return ret;
}

/*
 * scan pci devices to add all existed PCI devices to alldevs_list,
 * and setup pci hierarchy in array bus2bridge. This function is only
 * called in VT-d hardware setup
 */
int __init scan_pci_devices(void)
{
    struct pci_dev *pdev;
    int bus, dev, func;
    u8 sec_bus, sub_bus;
    int type;
    u32 l;

    spin_lock(&pcidevs_lock);
    for ( bus = 0; bus < 256; bus++ )
    {
        for ( dev = 0; dev < 32; dev++ )
        {
            for ( func = 0; func < 8; func++ )
            {
                l = pci_conf_read32(bus, dev, func, PCI_VENDOR_ID);
                /* some broken boards return 0 or ~0 if a slot is empty: */
                if ( (l == 0xffffffff) || (l == 0x00000000) ||
                     (l == 0x0000ffff) || (l == 0xffff0000) )
                    continue;

                pdev = alloc_pdev(bus, PCI_DEVFN(dev, func));
                if ( !pdev )
                {
                    printk("%s: alloc_pdev failed.\n", __func__);
                    spin_unlock(&pcidevs_lock);
                    return -ENOMEM;
                }

                /* build bus2bridge */
                type = pdev_type(bus, PCI_DEVFN(dev, func));
                switch ( type )
                {
                    case DEV_TYPE_PCIe_BRIDGE:
                        break;

                    case DEV_TYPE_PCIe2PCI_BRIDGE:
                    case DEV_TYPE_LEGACY_PCI_BRIDGE:
                        sec_bus = pci_conf_read8(bus, dev, func,
                                                 PCI_SECONDARY_BUS);
                        sub_bus = pci_conf_read8(bus, dev, func,
                                                 PCI_SUBORDINATE_BUS);

                        spin_lock(&bus2bridge_lock);
                        for ( sub_bus &= 0xff; sec_bus <= sub_bus; sec_bus++ )
                        {
                            bus2bridge[sec_bus].map = 1;
                            bus2bridge[sec_bus].bus =  bus;
                            bus2bridge[sec_bus].devfn =  PCI_DEVFN(dev, func);
                        }
                        spin_unlock(&bus2bridge_lock);
                        break;

                    case DEV_TYPE_PCIe_ENDPOINT:
                    case DEV_TYPE_PCI:
                        break;

                    default:
                        printk("%s: unknown type: bdf = %x:%x.%x\n",
                               __func__, bus, dev, func);
                        spin_unlock(&pcidevs_lock);
                        return -EINVAL;
                }
            }
        }
    }

    spin_unlock(&pcidevs_lock);
    return 0;
}

#ifdef SUPPORT_MSI_REMAPPING
static void dump_pci_devices(unsigned char ch)
{
    struct pci_dev *pdev;
    struct msi_desc *msi;

    printk("==== PCI devices ====\n");
    spin_lock(&pcidevs_lock);

    list_for_each_entry ( pdev, &alldevs_list, alldevs_list )
    {
        printk("%02x:%02x.%x - dom %-3d - MSIs < ",
               pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn),
               pdev->domain ? pdev->domain->domain_id : -1);
        list_for_each_entry ( msi, &pdev->msi_list, list )
               printk("%d ", msi->irq);
        printk(">\n");
    }

    spin_unlock(&pcidevs_lock);
}

struct keyhandler dump_pci_devices_keyhandler = {
    .diagnostic = 1,
    .u.fn = dump_pci_devices,
    .desc = "dump PCI devices"
};

static int __init setup_dump_pcidevs(void)
{
    register_keyhandler('Q', &dump_pci_devices_keyhandler);
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
