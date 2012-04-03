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
#include <xen/irq.h>
#include <asm/hvm/iommu.h>
#include <asm/hvm/irq.h>
#include <xen/delay.h>
#include <xen/keyhandler.h>
#include <xen/radix-tree.h>
#include <xen/tasklet.h>
#include <xsm/xsm.h>
#ifdef CONFIG_X86
#include <asm/msi.h>
#endif

struct pci_seg {
    struct list_head alldevs_list;
    u16 nr;
    /* bus2bridge_lock protects bus2bridge array */
    spinlock_t bus2bridge_lock;
#define MAX_BUSES 256
    struct {
        u8 map;
        u8 bus;
        u8 devfn;
    } bus2bridge[MAX_BUSES];
};

spinlock_t pcidevs_lock = SPIN_LOCK_UNLOCKED;
static struct radix_tree_root pci_segments;

static inline struct pci_seg *get_pseg(u16 seg)
{
    return radix_tree_lookup(&pci_segments, seg);
}

bool_t pci_known_segment(u16 seg)
{
    return get_pseg(seg) != NULL;
}

static struct pci_seg *alloc_pseg(u16 seg)
{
    struct pci_seg *pseg = get_pseg(seg);

    if ( pseg )
        return pseg;

    pseg = xzalloc(struct pci_seg);
    if ( !pseg )
        return NULL;

    pseg->nr = seg;
    INIT_LIST_HEAD(&pseg->alldevs_list);
    spin_lock_init(&pseg->bus2bridge_lock);

    if ( radix_tree_insert(&pci_segments, seg, pseg) )
    {
        xfree(pseg);
        pseg = NULL;
    }

    return pseg;
}

static int pci_segments_iterate(
    int (*handler)(struct pci_seg *, void *), void *arg)
{
    u16 seg = 0;
    int rc = 0;

    do {
        struct pci_seg *pseg;

        if ( !radix_tree_gang_lookup(&pci_segments, (void **)&pseg, seg, 1) )
            break;
        rc = handler(pseg, arg);
        seg = pseg->nr + 1;
    } while (!rc && seg);

    return rc;
}

void __init pt_pci_init(void)
{
    radix_tree_init(&pci_segments);
    if ( !alloc_pseg(0) )
        panic("Could not initialize PCI segment 0\n");
}

int __init pci_add_segment(u16 seg)
{
    return alloc_pseg(seg) ? 0 : -ENOMEM;
}

static struct pci_dev *alloc_pdev(struct pci_seg *pseg, u8 bus, u8 devfn)
{
    struct pci_dev *pdev;

    list_for_each_entry ( pdev, &pseg->alldevs_list, alldevs_list )
        if ( pdev->bus == bus && pdev->devfn == devfn )
            return pdev;

    pdev = xzalloc(struct pci_dev);
    if ( !pdev )
        return NULL;

    *(u16*) &pdev->seg = pseg->nr;
    *((u8*) &pdev->bus) = bus;
    *((u8*) &pdev->devfn) = devfn;
    pdev->domain = NULL;
    INIT_LIST_HEAD(&pdev->msi_list);
    list_add(&pdev->alldevs_list, &pseg->alldevs_list);
    spin_lock_init(&pdev->msix_table_lock);

    /* update bus2bridge */
    switch ( pdev_type(pseg->nr, bus, devfn) )
    {
        u8 sec_bus, sub_bus;

        case DEV_TYPE_PCIe_BRIDGE:
            break;

        case DEV_TYPE_PCIe2PCI_BRIDGE:
        case DEV_TYPE_LEGACY_PCI_BRIDGE:
            sec_bus = pci_conf_read8(pseg->nr, bus, PCI_SLOT(devfn),
                                     PCI_FUNC(devfn), PCI_SECONDARY_BUS);
            sub_bus = pci_conf_read8(pseg->nr, bus, PCI_SLOT(devfn),
                                     PCI_FUNC(devfn), PCI_SUBORDINATE_BUS);

            spin_lock(&pseg->bus2bridge_lock);
            for ( ; sec_bus <= sub_bus; sec_bus++ )
            {
                pseg->bus2bridge[sec_bus].map = 1;
                pseg->bus2bridge[sec_bus].bus = bus;
                pseg->bus2bridge[sec_bus].devfn = devfn;
            }
            spin_unlock(&pseg->bus2bridge_lock);
            break;

        case DEV_TYPE_PCIe_ENDPOINT:
        case DEV_TYPE_PCI:
            break;

        default:
            printk(XENLOG_WARNING "%s: unknown type: %04x:%02x:%02x.%u\n",
                   __func__, pseg->nr, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
            break;
    }

    return pdev;
}

static void free_pdev(struct pci_seg *pseg, struct pci_dev *pdev)
{
    /* update bus2bridge */
    switch ( pdev_type(pseg->nr, pdev->bus, pdev->devfn) )
    {
        u8 dev, func, sec_bus, sub_bus;

        case DEV_TYPE_PCIe2PCI_BRIDGE:
        case DEV_TYPE_LEGACY_PCI_BRIDGE:
            dev = PCI_SLOT(pdev->devfn);
            func = PCI_FUNC(pdev->devfn);
            sec_bus = pci_conf_read8(pseg->nr, pdev->bus, dev, func,
                                     PCI_SECONDARY_BUS);
            sub_bus = pci_conf_read8(pseg->nr, pdev->bus, dev, func,
                                     PCI_SUBORDINATE_BUS);

            spin_lock(&pseg->bus2bridge_lock);
            for ( ; sec_bus <= sub_bus; sec_bus++ )
                pseg->bus2bridge[sec_bus] = pseg->bus2bridge[pdev->bus];
            spin_unlock(&pseg->bus2bridge_lock);
            break;
    }

    list_del(&pdev->alldevs_list);
    xfree(pdev);
}

struct pci_dev *pci_get_pdev(int seg, int bus, int devfn)
{
    struct pci_seg *pseg = get_pseg(seg);
    struct pci_dev *pdev = NULL;

    ASSERT(spin_is_locked(&pcidevs_lock));
    ASSERT(seg != -1 || bus == -1);
    ASSERT(bus != -1 || devfn == -1);

    if ( !pseg )
    {
        if ( seg == -1 )
            radix_tree_gang_lookup(&pci_segments, (void **)&pseg, 0, 1);
        if ( !pseg )
            return NULL;
    }

    do {
        list_for_each_entry ( pdev, &pseg->alldevs_list, alldevs_list )
            if ( (pdev->bus == bus || bus == -1) &&
                 (pdev->devfn == devfn || devfn == -1) )
                return pdev;
    } while ( radix_tree_gang_lookup(&pci_segments, (void **)&pseg,
                                     pseg->nr + 1, 1) );

    return NULL;
}

struct pci_dev *pci_get_pdev_by_domain(
    struct domain *d, int seg, int bus, int devfn)
{
    struct pci_seg *pseg = get_pseg(seg);
    struct pci_dev *pdev = NULL;

    ASSERT(seg != -1 || bus == -1);
    ASSERT(bus != -1 || devfn == -1);

    if ( !pseg )
    {
        if ( seg == -1 )
            radix_tree_gang_lookup(&pci_segments, (void **)&pseg, 0, 1);
        if ( !pseg )
            return NULL;
    }

    do {
        list_for_each_entry ( pdev, &pseg->alldevs_list, alldevs_list )
            if ( (pdev->bus == bus || bus == -1) &&
                 (pdev->devfn == devfn || devfn == -1) &&
                 (pdev->domain == d) )
                return pdev;
    } while ( radix_tree_gang_lookup(&pci_segments, (void **)&pseg,
                                     pseg->nr + 1, 1) );

    return NULL;
}

/**
 * pci_enable_acs - enable ACS if hardware support it
 * @dev: the PCI device
 */
static void pci_enable_acs(struct pci_dev *pdev)
{
    int pos;
    u16 cap, ctrl, seg = pdev->seg;
    u8 bus = pdev->bus;
    u8 dev = PCI_SLOT(pdev->devfn);
    u8 func = PCI_FUNC(pdev->devfn);

    if ( !iommu_enabled )
        return;

    pos = pci_find_ext_capability(seg, bus, pdev->devfn, PCI_EXT_CAP_ID_ACS);
    if (!pos)
        return;

    cap = pci_conf_read16(seg, bus, dev, func, pos + PCI_ACS_CAP);
    ctrl = pci_conf_read16(seg, bus, dev, func, pos + PCI_ACS_CTRL);

    /* Source Validation */
    ctrl |= (cap & PCI_ACS_SV);

    /* P2P Request Redirect */
    ctrl |= (cap & PCI_ACS_RR);

    /* P2P Completion Redirect */
    ctrl |= (cap & PCI_ACS_CR);

    /* Upstream Forwarding */
    ctrl |= (cap & PCI_ACS_UF);

    pci_conf_write16(seg, bus, dev, func, pos + PCI_ACS_CTRL, ctrl);
}

int pci_add_device(u16 seg, u8 bus, u8 devfn, const struct pci_dev_info *info)
{
    struct pci_seg *pseg;
    struct pci_dev *pdev;
    unsigned int slot = PCI_SLOT(devfn), func = PCI_FUNC(devfn);
    const char *pdev_type;
    int ret;

    if (!info)
        pdev_type = "device";
    else if (info->is_extfn)
        pdev_type = "extended function";
    else if (info->is_virtfn)
    {
        spin_lock(&pcidevs_lock);
        pdev = pci_get_pdev(seg, info->physfn.bus, info->physfn.devfn);
        spin_unlock(&pcidevs_lock);
        if ( !pdev )
            pci_add_device(seg, info->physfn.bus, info->physfn.devfn, NULL);
        pdev_type = "virtual function";
    }
    else
    {
        info = NULL;
        pdev_type = "device";
    }

    ret = xsm_resource_plug_pci((seg << 16) | (bus << 8) | devfn);
    if ( ret )
        return ret;

    ret = -ENOMEM;

    spin_lock(&pcidevs_lock);
    pseg = alloc_pseg(seg);
    if ( !pseg )
        goto out;
    pdev = alloc_pdev(pseg, bus, devfn);
    if ( !pdev )
        goto out;

    if ( info )
        pdev->info = *info;
    else if ( !pdev->vf_rlen[0] )
    {
        unsigned int pos = pci_find_ext_capability(seg, bus, devfn,
                                                   PCI_EXT_CAP_ID_SRIOV);
        u16 ctrl = pci_conf_read16(seg, bus, slot, func, pos + PCI_SRIOV_CTRL);

        if ( !pos )
            /* Nothing */;
        else if ( !(ctrl & (PCI_SRIOV_CTRL_VFE | PCI_SRIOV_CTRL_MSE)) )
        {
            unsigned int i;

            BUILD_BUG_ON(ARRAY_SIZE(pdev->vf_rlen) != PCI_SRIOV_NUM_BARS);
            for ( i = 0; i < PCI_SRIOV_NUM_BARS; ++i )
            {
                unsigned int idx = pos + PCI_SRIOV_BAR + i * 4;
                u32 bar = pci_conf_read32(seg, bus, slot, func, idx);
                u32 hi = 0;

                if ( (bar & PCI_BASE_ADDRESS_SPACE) ==
                     PCI_BASE_ADDRESS_SPACE_IO )
                {
                    printk(XENLOG_WARNING
                           "SR-IOV device %04x:%02x:%02x.%u with vf BAR%u"
                           " in IO space\n",
                           seg, bus, slot, func, i);
                    continue;
                }
                pci_conf_write32(seg, bus, slot, func, idx, ~0);
                if ( (bar & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
                     PCI_BASE_ADDRESS_MEM_TYPE_64 )
                {
                    if ( i >= PCI_SRIOV_NUM_BARS )
                    {
                        printk(XENLOG_WARNING
                               "SR-IOV device %04x:%02x:%02x.%u with 64-bit"
                               " vf BAR in last slot\n",
                               seg, bus, slot, func);
                        break;
                    }
                    hi = pci_conf_read32(seg, bus, slot, func, idx + 4);
                    pci_conf_write32(seg, bus, slot, func, idx + 4, ~0);
                }
                pdev->vf_rlen[i] = pci_conf_read32(seg, bus, slot, func, idx) &
                                   PCI_BASE_ADDRESS_MEM_MASK;
                if ( (bar & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
                     PCI_BASE_ADDRESS_MEM_TYPE_64 )
                {
                    pdev->vf_rlen[i] |= (u64)pci_conf_read32(seg, bus,
                                                             slot, func,
                                                             idx + 4) << 32;
                    pci_conf_write32(seg, bus, slot, func, idx + 4, hi);
                }
                else if ( pdev->vf_rlen[i] )
                    pdev->vf_rlen[i] |= (u64)~0 << 32;
                pci_conf_write32(seg, bus, slot, func, idx, bar);
                pdev->vf_rlen[i] = -pdev->vf_rlen[i];
                if ( (bar & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
                     PCI_BASE_ADDRESS_MEM_TYPE_64 )
                    ++i;
            }
        }
        else
            printk(XENLOG_WARNING
                   "SR-IOV device %04x:%02x:%02x.%u has its virtual"
                   " functions already enabled (%04x)\n",
                   seg, bus, slot, func, ctrl);
    }

    ret = 0;
    if ( !pdev->domain )
    {
        pdev->domain = dom0;
        ret = iommu_add_device(pdev);
        if ( ret )
        {
            pdev->domain = NULL;
            goto out;
        }

        list_add(&pdev->domain_list, &dom0->arch.pdev_list);
    }
    else
        iommu_enable_device(pdev);

    pci_enable_acs(pdev);

out:
    spin_unlock(&pcidevs_lock);
    printk(XENLOG_DEBUG "PCI add %s %04x:%02x:%02x.%u\n", pdev_type,
           seg, bus, slot, func);
    return ret;
}

int pci_remove_device(u16 seg, u8 bus, u8 devfn)
{
    struct pci_seg *pseg = get_pseg(seg);
    struct pci_dev *pdev;
    int ret;

    ret = xsm_resource_unplug_pci((seg << 16) | (bus << 8) | devfn);
    if ( ret )
        return ret;

    ret = -ENODEV;

    if ( !pseg )
        return -ENODEV;

    spin_lock(&pcidevs_lock);
    list_for_each_entry ( pdev, &pseg->alldevs_list, alldevs_list )
        if ( pdev->bus == bus && pdev->devfn == devfn )
        {
            ret = iommu_remove_device(pdev);
            if ( pdev->domain )
                list_del(&pdev->domain_list);
            pci_cleanup_msi(pdev);
            free_pdev(pseg, pdev);
            printk(XENLOG_DEBUG "PCI remove device %04x:%02x:%02x.%u\n",
                   seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
            break;
        }

    spin_unlock(&pcidevs_lock);
    return ret;
}

static int pci_clean_dpci_irq(struct domain *d,
                              struct hvm_pirq_dpci *pirq_dpci, void *arg)
{
    struct dev_intx_gsi_link *digl, *tmp;

    pirq_guest_unbind(d, dpci_pirq(pirq_dpci));

    if ( pt_irq_need_timer(pirq_dpci->flags) )
        kill_timer(&pirq_dpci->timer);

    list_for_each_entry_safe ( digl, tmp, &pirq_dpci->digl_list, list )
    {
        list_del(&digl->list);
        xfree(digl);
    }

    return 0;
}

static void pci_clean_dpci_irqs(struct domain *d)
{
    struct hvm_irq_dpci *hvm_irq_dpci = NULL;

    if ( !iommu_enabled )
        return;

    if ( !is_hvm_domain(d) )
        return;

    spin_lock(&d->event_lock);
    hvm_irq_dpci = domain_get_irq_dpci(d);
    if ( hvm_irq_dpci != NULL )
    {
        tasklet_kill(&hvm_irq_dpci->dirq_tasklet);

        pt_pirq_iterate(d, pci_clean_dpci_irq, NULL);

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
    while ( (pdev = pci_get_pdev_by_domain(d, -1, -1, -1)) )
    {
        pci_cleanup_msi(pdev);
        bus = pdev->bus;
        devfn = pdev->devfn;
        if ( deassign_device(d, pdev->seg, bus, devfn) )
            printk("domain %d: deassign device (%04x:%02x:%02x.%u) failed!\n",
                   d->domain_id, pdev->seg, bus,
                   PCI_SLOT(devfn), PCI_FUNC(devfn));
    }
    spin_unlock(&pcidevs_lock);
}

#define PCI_CLASS_BRIDGE_PCI     0x0604

int pdev_type(u16 seg, u8 bus, u8 devfn)
{
    u16 class_device;
    u16 status, creg;
    int pos;
    u8 d = PCI_SLOT(devfn), f = PCI_FUNC(devfn);

    class_device = pci_conf_read16(seg, bus, d, f, PCI_CLASS_DEVICE);
    if ( class_device == PCI_CLASS_BRIDGE_PCI )
    {
        pos = pci_find_next_cap(seg, bus, devfn,
                                PCI_CAPABILITY_LIST, PCI_CAP_ID_EXP);
        if ( !pos )
            return DEV_TYPE_LEGACY_PCI_BRIDGE;
        creg = pci_conf_read16(seg, bus, d, f, pos + PCI_EXP_FLAGS);
        return ((creg & PCI_EXP_FLAGS_TYPE) >> 4) == PCI_EXP_TYPE_PCI_BRIDGE ?
            DEV_TYPE_PCIe2PCI_BRIDGE : DEV_TYPE_PCIe_BRIDGE;
    }

    status = pci_conf_read16(seg, bus, d, f, PCI_STATUS);
    if ( !(status & PCI_STATUS_CAP_LIST) )
        return DEV_TYPE_PCI;

    if ( pci_find_next_cap(seg, bus, devfn, PCI_CAPABILITY_LIST,
                           PCI_CAP_ID_EXP) )
        return DEV_TYPE_PCIe_ENDPOINT;

    return DEV_TYPE_PCI;
}

/*
 * find the upstream PCIe-to-PCI/PCIX bridge or PCI legacy bridge
 * return 0: the device is integrated PCI device or PCIe
 * return 1: find PCIe-to-PCI/PCIX bridge or PCI legacy bridge
 * return -1: fail
 */
int find_upstream_bridge(u16 seg, u8 *bus, u8 *devfn, u8 *secbus)
{
    struct pci_seg *pseg = get_pseg(seg);
    int ret = 0;
    int cnt = 0;

    if ( *bus == 0 )
        return 0;

    if ( !pseg )
        return -1;

    if ( !pseg->bus2bridge[*bus].map )
        return 0;

    ret = 1;
    spin_lock(&pseg->bus2bridge_lock);
    while ( pseg->bus2bridge[*bus].map )
    {
        *secbus = *bus;
        *devfn = pseg->bus2bridge[*bus].devfn;
        *bus = pseg->bus2bridge[*bus].bus;
        if ( cnt++ >= MAX_BUSES )
        {
            ret = -1;
            goto out;
        }
    }

out:
    spin_unlock(&pseg->bus2bridge_lock);
    return ret;
}

/*
 * detect pci device, return 0 if it exists, or return 0
 */
int __init pci_device_detect(u16 seg, u8 bus, u8 dev, u8 func)
{
    u32 vendor;

    vendor = pci_conf_read32(seg, bus, dev, func, PCI_VENDOR_ID);
    /* some broken boards return 0 or ~0 if a slot is empty: */
    if ( (vendor == 0xffffffff) || (vendor == 0x00000000) ||
         (vendor == 0x0000ffff) || (vendor == 0xffff0000) )
        return 0;
    return 1;
}

/*
 * scan pci devices to add all existed PCI devices to alldevs_list,
 * and setup pci hierarchy in array bus2bridge.
 */
static int __init _scan_pci_devices(struct pci_seg *pseg, void *arg)
{
    struct pci_dev *pdev;
    int bus, dev, func;

    for ( bus = 0; bus < 256; bus++ )
    {
        for ( dev = 0; dev < 32; dev++ )
        {
            for ( func = 0; func < 8; func++ )
            {
                if ( pci_device_detect(pseg->nr, bus, dev, func) == 0 )
                    continue;

                pdev = alloc_pdev(pseg, bus, PCI_DEVFN(dev, func));
                if ( !pdev )
                {
                    printk("%s: alloc_pdev failed.\n", __func__);
                    return -ENOMEM;
                }

                if ( !func && !(pci_conf_read8(pseg->nr, bus, dev, func,
                                               PCI_HEADER_TYPE) & 0x80) )
                    break;
            }
        }
    }

    return 0;
}

int __init scan_pci_devices(void)
{
    int ret;

    spin_lock(&pcidevs_lock);
    ret = pci_segments_iterate(_scan_pci_devices, NULL);
    spin_unlock(&pcidevs_lock);

    return ret;
}

struct setup_dom0 {
    struct domain *d;
    void (*handler)(struct pci_dev *);
};

static int __init _setup_dom0_pci_devices(struct pci_seg *pseg, void *arg)
{
    struct setup_dom0 *ctxt = arg;
    int bus, devfn;

    for ( bus = 0; bus < 256; bus++ )
    {
        for ( devfn = 0; devfn < 256; devfn++ )
        {
            struct pci_dev *pdev = pci_get_pdev(pseg->nr, bus, devfn);

            if ( !pdev )
                continue;

            pdev->domain = ctxt->d;
            list_add(&pdev->domain_list, &ctxt->d->arch.pdev_list);
            ctxt->handler(pdev);
        }
    }

    return 0;
}

void __init setup_dom0_pci_devices(
    struct domain *d, void (*handler)(struct pci_dev *))
{
    struct setup_dom0 ctxt = { .d = d, .handler = handler };

    spin_lock(&pcidevs_lock);
    pci_segments_iterate(_setup_dom0_pci_devices, &ctxt);
    spin_unlock(&pcidevs_lock);
}

static int _dump_pci_devices(struct pci_seg *pseg, void *arg)
{
    struct pci_dev *pdev;
    struct msi_desc *msi;

    printk("==== segment %04x ====\n", pseg->nr);

    list_for_each_entry ( pdev, &pseg->alldevs_list, alldevs_list )
    {
        printk("%04x:%02x:%02x.%u - dom %-3d - MSIs < ",
               pseg->nr, pdev->bus,
               PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn),
               pdev->domain ? pdev->domain->domain_id : -1);
        list_for_each_entry ( msi, &pdev->msi_list, list )
               printk("%d ", msi->irq);
        printk(">\n");
    }

    return 0;
}

static void dump_pci_devices(unsigned char ch)
{
    printk("==== PCI devices ====\n");
    spin_lock(&pcidevs_lock);
    pci_segments_iterate(_dump_pci_devices, NULL);
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
