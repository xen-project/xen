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
 * this program; If not, see <http://www.gnu.org/licenses/>.
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
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/paging.h>
#include <xen/radix-tree.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>
#include <xsm/xsm.h>
#include <asm/msi.h>

struct pci_seg {
    struct list_head alldevs_list;
    u16 nr;
    unsigned long *ro_map;
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
        panic("Could not initialize PCI segment 0");
}

int __init pci_add_segment(u16 seg)
{
    return alloc_pseg(seg) ? 0 : -ENOMEM;
}

const unsigned long *pci_get_ro_map(u16 seg)
{
    struct pci_seg *pseg = get_pseg(seg);

    return pseg ? pseg->ro_map : NULL;
}

static struct phantom_dev {
    u16 seg;
    u8 bus, slot, stride;
} phantom_devs[8];
static unsigned int nr_phantom_devs;

static void __init parse_phantom_dev(char *str) {
    const char *s = str;
    unsigned int seg, bus, slot;
    struct phantom_dev phantom;

    if ( !s || !*s || nr_phantom_devs >= ARRAY_SIZE(phantom_devs) )
        return;

    s = parse_pci(s, &seg, &bus, &slot, NULL);
    if ( !s || *s != ',' )
        return;

    phantom.seg = seg;
    phantom.bus = bus;
    phantom.slot = slot;

    switch ( phantom.stride = simple_strtol(s + 1, &s, 0) )
    {
    case 1: case 2: case 4:
        if ( *s )
    default:
            return;
    }

    phantom_devs[nr_phantom_devs++] = phantom;
}
custom_param("pci-phantom", parse_phantom_dev);

static u16 __read_mostly command_mask;
static u16 __read_mostly bridge_ctl_mask;

/*
 * The 'pci' parameter controls certain PCI device aspects.
 * Optional comma separated value may contain:
 *
 *   serr                       don't suppress system errors (default)
 *   no-serr                    suppress system errors
 *   perr                       don't suppress parity errors (default)
 *   no-perr                    suppress parity errors
 */
static void __init parse_pci_param(char *s)
{
    char *ss;

    do {
        bool_t on = !!strncmp(s, "no-", 3);
        u16 cmd_mask = 0, brctl_mask = 0;

        if ( !on )
            s += 3;

        ss = strchr(s, ',');
        if ( ss )
            *ss = '\0';

        if ( !strcmp(s, "serr") )
        {
            cmd_mask = PCI_COMMAND_SERR;
            brctl_mask = PCI_BRIDGE_CTL_SERR | PCI_BRIDGE_CTL_DTMR_SERR;
        }
        else if ( !strcmp(s, "perr") )
        {
            cmd_mask = PCI_COMMAND_PARITY;
            brctl_mask = PCI_BRIDGE_CTL_PARITY;
        }

        if ( on )
        {
            command_mask &= ~cmd_mask;
            bridge_ctl_mask &= ~brctl_mask;
        }
        else
        {
            command_mask |= cmd_mask;
            bridge_ctl_mask |= brctl_mask;
        }

        s = ss + 1;
    } while ( ss );
}
custom_param("pci", parse_pci_param);

static void check_pdev(const struct pci_dev *pdev)
{
#define PCI_STATUS_CHECK \
    (PCI_STATUS_PARITY | PCI_STATUS_SIG_TARGET_ABORT | \
     PCI_STATUS_REC_TARGET_ABORT | PCI_STATUS_REC_MASTER_ABORT | \
     PCI_STATUS_SIG_SYSTEM_ERROR | PCI_STATUS_DETECTED_PARITY)
    u16 seg = pdev->seg;
    u8 bus = pdev->bus;
    u8 dev = PCI_SLOT(pdev->devfn);
    u8 func = PCI_FUNC(pdev->devfn);
    u16 val;

    if ( command_mask )
    {
        val = pci_conf_read16(seg, bus, dev, func, PCI_COMMAND);
        if ( val & command_mask )
            pci_conf_write16(seg, bus, dev, func, PCI_COMMAND,
                             val & ~command_mask);
        val = pci_conf_read16(seg, bus, dev, func, PCI_STATUS);
        if ( val & PCI_STATUS_CHECK )
        {
            printk(XENLOG_INFO "%04x:%02x:%02x.%u status %04x -> %04x\n",
                   seg, bus, dev, func, val, val & ~PCI_STATUS_CHECK);
            pci_conf_write16(seg, bus, dev, func, PCI_STATUS,
                             val & PCI_STATUS_CHECK);
        }
    }

    switch ( pci_conf_read8(seg, bus, dev, func, PCI_HEADER_TYPE) & 0x7f )
    {
    case PCI_HEADER_TYPE_BRIDGE:
        if ( !bridge_ctl_mask )
            break;
        val = pci_conf_read16(seg, bus, dev, func, PCI_BRIDGE_CONTROL);
        if ( val & bridge_ctl_mask )
            pci_conf_write16(seg, bus, dev, func, PCI_BRIDGE_CONTROL,
                             val & ~bridge_ctl_mask);
        val = pci_conf_read16(seg, bus, dev, func, PCI_SEC_STATUS);
        if ( val & PCI_STATUS_CHECK )
        {
            printk(XENLOG_INFO
                   "%04x:%02x:%02x.%u secondary status %04x -> %04x\n",
                   seg, bus, dev, func, val, val & ~PCI_STATUS_CHECK);
            pci_conf_write16(seg, bus, dev, func, PCI_SEC_STATUS,
                             val & PCI_STATUS_CHECK);
        }
        break;

    case PCI_HEADER_TYPE_CARDBUS:
        /* TODO */
        break;
    }
#undef PCI_STATUS_CHECK
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

    if ( pci_find_cap_offset(pseg->nr, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                             PCI_CAP_ID_MSIX) )
    {
        struct arch_msix *msix = xzalloc(struct arch_msix);

        if ( !msix )
        {
            xfree(pdev);
            return NULL;
        }
        spin_lock_init(&msix->table_lock);
        pdev->msix = msix;
    }

    list_add(&pdev->alldevs_list, &pseg->alldevs_list);

    /* update bus2bridge */
    switch ( pdev->type = pdev_type(pseg->nr, bus, devfn) )
    {
        int pos;
        u16 cap;
        u8 sec_bus, sub_bus;

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
            pos = pci_find_cap_offset(pseg->nr, bus, PCI_SLOT(devfn),
                                      PCI_FUNC(devfn), PCI_CAP_ID_EXP);
            BUG_ON(!pos);
            cap = pci_conf_read16(pseg->nr, bus, PCI_SLOT(devfn),
                                  PCI_FUNC(devfn), pos + PCI_EXP_DEVCAP);
            if ( cap & PCI_EXP_DEVCAP_PHANTOM )
            {
                pdev->phantom_stride = 8 >> MASK_EXTR(cap,
                                                      PCI_EXP_DEVCAP_PHANTOM);
                if ( PCI_FUNC(devfn) >= pdev->phantom_stride )
                    pdev->phantom_stride = 0;
            }
            else
            {
                unsigned int i;

                for ( i = 0; i < nr_phantom_devs; ++i )
                    if ( phantom_devs[i].seg == pseg->nr &&
                         phantom_devs[i].bus == bus &&
                         phantom_devs[i].slot == PCI_SLOT(devfn) &&
                         phantom_devs[i].stride > PCI_FUNC(devfn) )
                    {
                        pdev->phantom_stride = phantom_devs[i].stride;
                        break;
                    }
            }
            break;

        case DEV_TYPE_PCI:
        case DEV_TYPE_PCIe_BRIDGE:
        case DEV_TYPE_PCI_HOST_BRIDGE:
            break;

        default:
            printk(XENLOG_WARNING "%s: unknown type: %04x:%02x:%02x.%u\n",
                   __func__, pseg->nr, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
            break;
    }

    check_pdev(pdev);

    return pdev;
}

static void free_pdev(struct pci_seg *pseg, struct pci_dev *pdev)
{
    /* update bus2bridge */
    switch ( pdev->type )
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

        default:
            break;
    }

    list_del(&pdev->alldevs_list);
    xfree(pdev->msix);
    xfree(pdev);
}

static void _pci_hide_device(struct pci_dev *pdev)
{
    if ( pdev->domain )
        return;
    pdev->domain = dom_xen;
    list_add(&pdev->domain_list, &dom_xen->arch.pdev_list);
}

int __init pci_hide_device(int bus, int devfn)
{
    struct pci_dev *pdev;
    int rc = -ENOMEM;

    spin_lock(&pcidevs_lock);
    pdev = alloc_pdev(get_pseg(0), bus, devfn);
    if ( pdev )
    {
        _pci_hide_device(pdev);
        rc = 0;
    }
    spin_unlock(&pcidevs_lock);

    return rc;
}

int __init pci_ro_device(int seg, int bus, int devfn)
{
    struct pci_seg *pseg = alloc_pseg(seg);
    struct pci_dev *pdev;

    if ( !pseg )
        return -ENOMEM;
    pdev = alloc_pdev(pseg, bus, devfn);
    if ( !pdev )
        return -ENOMEM;

    if ( !pseg->ro_map )
    {
        size_t sz = BITS_TO_LONGS(PCI_BDF(-1, -1, -1) + 1) * sizeof(long);

        pseg->ro_map = alloc_xenheap_pages(get_order_from_bytes(sz), 0);
        if ( !pseg->ro_map )
            return -ENOMEM;
        memset(pseg->ro_map, 0, sz);
    }

    __set_bit(PCI_BDF2(bus, devfn), pseg->ro_map);
    _pci_hide_device(pdev);

    return 0;
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

struct pci_dev *pci_get_real_pdev(int seg, int bus, int devfn)
{
    struct pci_dev *pdev;
    int stride;

    if ( seg < 0 || bus < 0 || devfn < 0 )
        return NULL;

    for ( pdev = pci_get_pdev(seg, bus, devfn), stride = 4;
          !pdev && stride; stride >>= 1 )
    {
        if ( !(devfn & (8 - stride)) )
            continue;
        pdev = pci_get_pdev(seg, bus, devfn & ~(8 - stride));
        if ( pdev && stride != pdev->phantom_stride )
            pdev = NULL;
    }

    return pdev;
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

int pci_add_device(u16 seg, u8 bus, u8 devfn,
                   const struct pci_dev_info *info, nodeid_t node)
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
            pci_add_device(seg, info->physfn.bus, info->physfn.devfn,
                           NULL, node);
        pdev_type = "virtual function";
    }
    else
    {
        info = NULL;
        pdev_type = "device";
    }

    ret = xsm_resource_plug_pci(XSM_PRIV, (seg << 16) | (bus << 8) | devfn);
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

    pdev->node = node;

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

    check_pdev(pdev);

    ret = 0;
    if ( !pdev->domain )
    {
        pdev->domain = hardware_domain;
        ret = iommu_add_device(pdev);
        if ( ret )
        {
            pdev->domain = NULL;
            goto out;
        }

        list_add(&pdev->domain_list, &hardware_domain->arch.pdev_list);
    }
    else
        iommu_enable_device(pdev);

    pci_enable_acs(pdev);

out:
    spin_unlock(&pcidevs_lock);
    if ( !ret )
    {
        printk(XENLOG_DEBUG "PCI add %s %04x:%02x:%02x.%u\n", pdev_type,
               seg, bus, slot, func);
        while ( pdev->phantom_stride )
        {
            func += pdev->phantom_stride;
            if ( PCI_SLOT(func) )
                break;
            printk(XENLOG_DEBUG "PCI phantom %04x:%02x:%02x.%u\n",
                   seg, bus, slot, func);
        }
    }
    return ret;
}

int pci_remove_device(u16 seg, u8 bus, u8 devfn)
{
    struct pci_seg *pseg = get_pseg(seg);
    struct pci_dev *pdev;
    int ret;

    ret = xsm_resource_unplug_pci(XSM_PRIV, (seg << 16) | (bus << 8) | devfn);
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

    return pt_pirq_softirq_active(pirq_dpci) ? -ERESTART : 0;
}

static int pci_clean_dpci_irqs(struct domain *d)
{
    struct hvm_irq_dpci *hvm_irq_dpci = NULL;

    if ( !iommu_enabled )
        return 0;

    if ( !is_hvm_domain(d) )
        return 0;

    spin_lock(&d->event_lock);
    hvm_irq_dpci = domain_get_irq_dpci(d);
    if ( hvm_irq_dpci != NULL )
    {
        int ret = pt_pirq_iterate(d, pci_clean_dpci_irq, NULL);

        if ( ret )
        {
            spin_unlock(&d->event_lock);
            return ret;
        }

        d->arch.hvm_domain.irq.dpci = NULL;
        free_hvm_irq_dpci(hvm_irq_dpci);
    }
    spin_unlock(&d->event_lock);
    return 0;
}

int pci_release_devices(struct domain *d)
{
    struct pci_dev *pdev;
    u8 bus, devfn;
    int ret;

    spin_lock(&pcidevs_lock);
    ret = pci_clean_dpci_irqs(d);
    if ( ret )
    {
        spin_unlock(&pcidevs_lock);
        return ret;
    }
    while ( (pdev = pci_get_pdev_by_domain(d, -1, -1, -1)) )
    {
        bus = pdev->bus;
        devfn = pdev->devfn;
        if ( deassign_device(d, pdev->seg, bus, devfn) )
            printk("domain %d: deassign device (%04x:%02x:%02x.%u) failed!\n",
                   d->domain_id, pdev->seg, bus,
                   PCI_SLOT(devfn), PCI_FUNC(devfn));
    }
    spin_unlock(&pcidevs_lock);

    return 0;
}

#define PCI_CLASS_BRIDGE_HOST    0x0600
#define PCI_CLASS_BRIDGE_PCI     0x0604

enum pdev_type pdev_type(u16 seg, u8 bus, u8 devfn)
{
    u16 class_device, creg;
    u8 d = PCI_SLOT(devfn), f = PCI_FUNC(devfn);
    int pos = pci_find_cap_offset(seg, bus, d, f, PCI_CAP_ID_EXP);

    class_device = pci_conf_read16(seg, bus, d, f, PCI_CLASS_DEVICE);
    switch ( class_device )
    {
    case PCI_CLASS_BRIDGE_PCI:
        if ( !pos )
            return DEV_TYPE_LEGACY_PCI_BRIDGE;
        creg = pci_conf_read16(seg, bus, d, f, pos + PCI_EXP_FLAGS);
        switch ( (creg & PCI_EXP_FLAGS_TYPE) >> 4 )
        {
        case PCI_EXP_TYPE_PCI_BRIDGE:
            return DEV_TYPE_PCIe2PCI_BRIDGE;
        case PCI_EXP_TYPE_PCIE_BRIDGE:
            return DEV_TYPE_PCI2PCIe_BRIDGE;
        }
        return DEV_TYPE_PCIe_BRIDGE;
    case PCI_CLASS_BRIDGE_HOST:
        return DEV_TYPE_PCI_HOST_BRIDGE;

    case 0x0000: case 0xffff:
        return DEV_TYPE_PCI_UNKNOWN;
    }

    return pos ? DEV_TYPE_PCIe_ENDPOINT : DEV_TYPE_PCI;
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

bool_t __init pci_device_detect(u16 seg, u8 bus, u8 dev, u8 func)
{
    u32 vendor;

    vendor = pci_conf_read32(seg, bus, dev, func, PCI_VENDOR_ID);
    /* some broken boards return 0 or ~0 if a slot is empty: */
    if ( (vendor == 0xffffffff) || (vendor == 0x00000000) ||
         (vendor == 0x0000ffff) || (vendor == 0xffff0000) )
        return 0;
    return 1;
}

void pci_check_disable_device(u16 seg, u8 bus, u8 devfn)
{
    struct pci_dev *pdev;
    s_time_t now = NOW();
    u16 cword;

    spin_lock(&pcidevs_lock);
    pdev = pci_get_real_pdev(seg, bus, devfn);
    if ( pdev )
    {
        if ( now < pdev->fault.time ||
             now - pdev->fault.time > MILLISECS(10) )
            pdev->fault.count >>= 1;
        pdev->fault.time = now;
        if ( ++pdev->fault.count < PT_FAULT_THRESHOLD )
            pdev = NULL;
    }
    spin_unlock(&pcidevs_lock);

    if ( !pdev )
        return;

    /* Tell the device to stop DMAing; we can't rely on the guest to
     * control it for us. */
    devfn = pdev->devfn;
    cword = pci_conf_read16(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                            PCI_COMMAND);
    pci_conf_write16(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                     PCI_COMMAND, cword & ~PCI_COMMAND_MASTER);
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
                if ( !pci_device_detect(pseg->nr, bus, dev, func) )
                {
                    if ( !func )
                        break;
                    continue;
                }

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

struct setup_hwdom {
    struct domain *d;
    int (*handler)(u8 devfn, struct pci_dev *);
};

static void setup_one_hwdom_device(const struct setup_hwdom *ctxt,
                                  struct pci_dev *pdev)
{
    u8 devfn = pdev->devfn;

    do {
        int err = ctxt->handler(devfn, pdev);

        if ( err )
        {
            printk(XENLOG_ERR "setup %04x:%02x:%02x.%u for d%d failed (%d)\n",
                   pdev->seg, pdev->bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                   ctxt->d->domain_id, err);
            if ( devfn == pdev->devfn )
                return;
        }
        devfn += pdev->phantom_stride;
    } while ( devfn != pdev->devfn &&
              PCI_SLOT(devfn) == PCI_SLOT(pdev->devfn) );
}

static int __hwdom_init _setup_hwdom_pci_devices(struct pci_seg *pseg, void *arg)
{
    struct setup_hwdom *ctxt = arg;
    int bus, devfn;

    for ( bus = 0; bus < 256; bus++ )
    {
        for ( devfn = 0; devfn < 256; devfn++ )
        {
            struct pci_dev *pdev = pci_get_pdev(pseg->nr, bus, devfn);

            if ( !pdev )
                continue;

            if ( !pdev->domain )
            {
                pdev->domain = ctxt->d;
                list_add(&pdev->domain_list, &ctxt->d->arch.pdev_list);
                setup_one_hwdom_device(ctxt, pdev);
            }
            else if ( pdev->domain == dom_xen )
            {
                pdev->domain = ctxt->d;
                setup_one_hwdom_device(ctxt, pdev);
                pdev->domain = dom_xen;
            }
            else if ( pdev->domain != ctxt->d )
                printk(XENLOG_WARNING "Dom%d owning %04x:%02x:%02x.%u?\n",
                       pdev->domain->domain_id, pseg->nr, bus,
                       PCI_SLOT(devfn), PCI_FUNC(devfn));

            if ( iommu_verbose )
            {
                spin_unlock(&pcidevs_lock);
                process_pending_softirqs();
                spin_lock(&pcidevs_lock);
            }
        }

        if ( !iommu_verbose )
        {
            spin_unlock(&pcidevs_lock);
            process_pending_softirqs();
            spin_lock(&pcidevs_lock);
        }
    }

    return 0;
}

void __hwdom_init setup_hwdom_pci_devices(
    struct domain *d, int (*handler)(u8 devfn, struct pci_dev *))
{
    struct setup_hwdom ctxt = { .d = d, .handler = handler };

    spin_lock(&pcidevs_lock);
    pci_segments_iterate(_setup_hwdom_pci_devices, &ctxt);
    spin_unlock(&pcidevs_lock);
}

#ifdef CONFIG_ACPI
#include <acpi/acpi.h>
#include <acpi/apei.h>

static int hest_match_pci(const struct acpi_hest_aer_common *p,
                          const struct pci_dev *pdev)
{
    return ACPI_HEST_SEGMENT(p->bus) == pdev->seg &&
           ACPI_HEST_BUS(p->bus)     == pdev->bus &&
           p->device                 == PCI_SLOT(pdev->devfn) &&
           p->function               == PCI_FUNC(pdev->devfn);
}

static bool_t hest_match_type(const struct acpi_hest_header *hest_hdr,
                              const struct pci_dev *pdev)
{
    unsigned int pos = pci_find_cap_offset(pdev->seg, pdev->bus,
                                           PCI_SLOT(pdev->devfn),
                                           PCI_FUNC(pdev->devfn),
                                           PCI_CAP_ID_EXP);
    u8 pcie = MASK_EXTR(pci_conf_read16(pdev->seg, pdev->bus,
                                        PCI_SLOT(pdev->devfn),
                                        PCI_FUNC(pdev->devfn),
                                        pos + PCI_EXP_FLAGS),
                        PCI_EXP_FLAGS_TYPE);

    switch ( hest_hdr->type )
    {
    case ACPI_HEST_TYPE_AER_ROOT_PORT:
        return pcie == PCI_EXP_TYPE_ROOT_PORT;
    case ACPI_HEST_TYPE_AER_ENDPOINT:
        return pcie == PCI_EXP_TYPE_ENDPOINT;
    case ACPI_HEST_TYPE_AER_BRIDGE:
        return pci_conf_read16(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                               PCI_FUNC(pdev->devfn), PCI_CLASS_DEVICE) ==
               PCI_CLASS_BRIDGE_PCI;
    }

    return 0;
}

struct aer_hest_parse_info {
    const struct pci_dev *pdev;
    bool_t firmware_first;
};

static bool_t hest_source_is_pcie_aer(const struct acpi_hest_header *hest_hdr)
{
    if ( hest_hdr->type == ACPI_HEST_TYPE_AER_ROOT_PORT ||
         hest_hdr->type == ACPI_HEST_TYPE_AER_ENDPOINT ||
         hest_hdr->type == ACPI_HEST_TYPE_AER_BRIDGE )
        return 1;
    return 0;
}

static int aer_hest_parse(const struct acpi_hest_header *hest_hdr, void *data)
{
    struct aer_hest_parse_info *info = data;
    const struct acpi_hest_aer_common *p;
    bool_t ff;

    if ( !hest_source_is_pcie_aer(hest_hdr) )
        return 0;

    p = (const struct acpi_hest_aer_common *)(hest_hdr + 1);
    ff = !!(p->flags & ACPI_HEST_FIRMWARE_FIRST);

    /*
     * If no specific device is supplied, determine whether
     * FIRMWARE_FIRST is set for *any* PCIe device.
     */
    if ( !info->pdev )
    {
        info->firmware_first |= ff;
        return 0;
    }

    /* Otherwise, check the specific device */
    if ( p->flags & ACPI_HEST_GLOBAL ?
         hest_match_type(hest_hdr, info->pdev) :
         hest_match_pci(p, info->pdev) )
    {
        info->firmware_first = ff;
        return 1;
    }

    return 0;
}

bool_t pcie_aer_get_firmware_first(const struct pci_dev *pdev)
{
    struct aer_hest_parse_info info = { .pdev = pdev };

    return pci_find_cap_offset(pdev->seg, pdev->bus, PCI_SLOT(pdev->devfn),
                               PCI_FUNC(pdev->devfn), PCI_CAP_ID_EXP) &&
           apei_hest_parse(aer_hest_parse, &info) >= 0 &&
           info.firmware_first;
}
#endif

static int _dump_pci_devices(struct pci_seg *pseg, void *arg)
{
    struct pci_dev *pdev;
    struct msi_desc *msi;

    printk("==== segment %04x ====\n", pseg->nr);

    list_for_each_entry ( pdev, &pseg->alldevs_list, alldevs_list )
    {
        printk("%04x:%02x:%02x.%u - dom %-3d - node %-3d - MSIs < ",
               pseg->nr, pdev->bus,
               PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn),
               pdev->domain ? pdev->domain->domain_id : -1,
               (pdev->node != NUMA_NO_NODE) ? pdev->node : -1);
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

int iommu_update_ire_from_msi(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    const struct iommu_ops *ops = iommu_get_ops();
    return iommu_intremap ? ops->update_ire_from_msi(msi_desc, msg) : 0;
}

void iommu_read_msi_from_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    const struct iommu_ops *ops = iommu_get_ops();
    if ( iommu_intremap )
        ops->read_msi_from_ire(msi_desc, msg);
}

int iommu_add_device(struct pci_dev *pdev)
{
    struct hvm_iommu *hd;
    int rc;
    u8 devfn;

    if ( !pdev->domain )
        return -EINVAL;

    ASSERT(spin_is_locked(&pcidevs_lock));

    hd = domain_hvm_iommu(pdev->domain);
    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    rc = hd->platform_ops->add_device(pdev->devfn, pci_to_dev(pdev));
    if ( rc || !pdev->phantom_stride )
        return rc;

    for ( devfn = pdev->devfn ; ; )
    {
        devfn += pdev->phantom_stride;
        if ( PCI_SLOT(devfn) != PCI_SLOT(pdev->devfn) )
            return 0;
        rc = hd->platform_ops->add_device(devfn, pci_to_dev(pdev));
        if ( rc )
            printk(XENLOG_WARNING "IOMMU: add %04x:%02x:%02x.%u failed (%d)\n",
                   pdev->seg, pdev->bus, PCI_SLOT(devfn), PCI_FUNC(devfn), rc);
    }
}

int iommu_enable_device(struct pci_dev *pdev)
{
    struct hvm_iommu *hd;

    if ( !pdev->domain )
        return -EINVAL;

    ASSERT(spin_is_locked(&pcidevs_lock));

    hd = domain_hvm_iommu(pdev->domain);
    if ( !iommu_enabled || !hd->platform_ops ||
         !hd->platform_ops->enable_device )
        return 0;

    return hd->platform_ops->enable_device(pci_to_dev(pdev));
}

int iommu_remove_device(struct pci_dev *pdev)
{
    struct hvm_iommu *hd;
    u8 devfn;

    if ( !pdev->domain )
        return -EINVAL;

    hd = domain_hvm_iommu(pdev->domain);
    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    for ( devfn = pdev->devfn ; pdev->phantom_stride; )
    {
        int rc;

        devfn += pdev->phantom_stride;
        if ( PCI_SLOT(devfn) != PCI_SLOT(pdev->devfn) )
            break;
        rc = hd->platform_ops->remove_device(devfn, pci_to_dev(pdev));
        if ( !rc )
            continue;

        printk(XENLOG_ERR "IOMMU: remove %04x:%02x:%02x.%u failed (%d)\n",
               pdev->seg, pdev->bus, PCI_SLOT(devfn), PCI_FUNC(devfn), rc);
        return rc;
    }

    return hd->platform_ops->remove_device(pdev->devfn, pci_to_dev(pdev));
}

/*
 * If the device isn't owned by the hardware domain, it means it already
 * has been assigned to other domain, or it doesn't exist.
 */
static int device_assigned(u16 seg, u8 bus, u8 devfn)
{
    struct pci_dev *pdev;

    spin_lock(&pcidevs_lock);
    pdev = pci_get_pdev_by_domain(hardware_domain, seg, bus, devfn);
    spin_unlock(&pcidevs_lock);

    return pdev ? 0 : -EBUSY;
}

static int assign_device(struct domain *d, u16 seg, u8 bus, u8 devfn, u32 flag)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct pci_dev *pdev;
    int rc = 0;

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    /* Prevent device assign if mem paging or mem sharing have been 
     * enabled for this domain */
    if ( unlikely(!need_iommu(d) &&
            (d->arch.hvm_domain.mem_sharing_enabled ||
             d->vm_event->paging.ring_page ||
             p2m_get_hostp2m(d)->global_logdirty)) )
        return -EXDEV;

    if ( !spin_trylock(&pcidevs_lock) )
        return -ERESTART;

    rc = iommu_construct(d);
    if ( rc )
    {
        spin_unlock(&pcidevs_lock);
        return rc;
    }

    pdev = pci_get_pdev_by_domain(hardware_domain, seg, bus, devfn);
    if ( !pdev )
    {
        rc = pci_get_pdev(seg, bus, devfn) ? -EBUSY : -ENODEV;
        goto done;
    }

    pdev->fault.count = 0;

    if ( (rc = hd->platform_ops->assign_device(d, devfn, pci_to_dev(pdev), flag)) )
        goto done;

    for ( ; pdev->phantom_stride; rc = 0 )
    {
        devfn += pdev->phantom_stride;
        if ( PCI_SLOT(devfn) != PCI_SLOT(pdev->devfn) )
            break;
        rc = hd->platform_ops->assign_device(d, devfn, pci_to_dev(pdev), flag);
        if ( rc )
            printk(XENLOG_G_WARNING "d%d: assign %04x:%02x:%02x.%u failed (%d)\n",
                   d->domain_id, seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                   rc);
    }

 done:
    if ( !has_arch_pdevs(d) && need_iommu(d) )
        iommu_teardown(d);
    spin_unlock(&pcidevs_lock);

    return rc;
}

/* caller should hold the pcidevs_lock */
int deassign_device(struct domain *d, u16 seg, u8 bus, u8 devfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct pci_dev *pdev = NULL;
    int ret = 0;

    if ( !iommu_enabled || !hd->platform_ops )
        return -EINVAL;

    ASSERT(spin_is_locked(&pcidevs_lock));
    pdev = pci_get_pdev_by_domain(d, seg, bus, devfn);
    if ( !pdev )
        return -ENODEV;

    while ( pdev->phantom_stride )
    {
        devfn += pdev->phantom_stride;
        if ( PCI_SLOT(devfn) != PCI_SLOT(pdev->devfn) )
            break;
        ret = hd->platform_ops->reassign_device(d, hardware_domain, devfn,
                                                pci_to_dev(pdev));
        if ( !ret )
            continue;

        printk(XENLOG_G_ERR "d%d: deassign %04x:%02x:%02x.%u failed (%d)\n",
               d->domain_id, seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), ret);
        return ret;
    }

    devfn = pdev->devfn;
    ret = hd->platform_ops->reassign_device(d, hardware_domain, devfn,
                                            pci_to_dev(pdev));
    if ( ret )
    {
        dprintk(XENLOG_G_ERR,
                "d%d: deassign device (%04x:%02x:%02x.%u) failed\n",
                d->domain_id, seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        return ret;
    }

    pdev->fault.count = 0;

    if ( !has_arch_pdevs(d) && need_iommu(d) )
        iommu_teardown(d);

    return ret;
}

static int iommu_get_device_group(
    struct domain *d, u16 seg, u8 bus, u8 devfn,
    XEN_GUEST_HANDLE_64(uint32) buf, int max_sdevs)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct pci_dev *pdev;
    int group_id, sdev_id;
    u32 bdf;
    int i = 0;
    const struct iommu_ops *ops = hd->platform_ops;

    if ( !iommu_enabled || !ops || !ops->get_device_group_id )
        return 0;

    group_id = ops->get_device_group_id(seg, bus, devfn);

    spin_lock(&pcidevs_lock);
    for_each_pdev( d, pdev )
    {
        if ( (pdev->seg != seg) ||
             ((pdev->bus == bus) && (pdev->devfn == devfn)) )
            continue;

        if ( xsm_get_device_group(XSM_HOOK, (seg << 16) | (pdev->bus << 8) | pdev->devfn) )
            continue;

        sdev_id = ops->get_device_group_id(seg, pdev->bus, pdev->devfn);
        if ( (sdev_id == group_id) && (i < max_sdevs) )
        {
            bdf = 0;
            bdf |= (pdev->bus & 0xff) << 16;
            bdf |= (pdev->devfn & 0xff) << 8;

            if ( unlikely(copy_to_guest_offset(buf, i, &bdf, 1)) )
            {
                spin_unlock(&pcidevs_lock);
                return -1;
            }
            i++;
        }
    }

    spin_unlock(&pcidevs_lock);

    return i;
}

int iommu_do_pci_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    u16 seg;
    u8 bus, devfn;
    u32 flag;
    int ret = 0;
    uint32_t machine_sbdf;

    switch ( domctl->cmd )
    {
    case XEN_DOMCTL_get_device_group:
    {
        u32 max_sdevs;
        XEN_GUEST_HANDLE_64(uint32) sdevs;

        ret = xsm_get_device_group(XSM_HOOK, domctl->u.get_device_group.machine_sbdf);
        if ( ret )
            break;

        seg = domctl->u.get_device_group.machine_sbdf >> 16;
        bus = PCI_BUS(domctl->u.get_device_group.machine_sbdf);
        devfn = PCI_DEVFN2(domctl->u.get_device_group.machine_sbdf);
        max_sdevs = domctl->u.get_device_group.max_sdevs;
        sdevs = domctl->u.get_device_group.sdev_array;

        ret = iommu_get_device_group(d, seg, bus, devfn, sdevs, max_sdevs);
        if ( ret < 0 )
        {
            dprintk(XENLOG_ERR, "iommu_get_device_group() failed!\n");
            ret = -EFAULT;
            domctl->u.get_device_group.num_sdevs = 0;
        }
        else
        {
            domctl->u.get_device_group.num_sdevs = ret;
            ret = 0;
        }
        if ( __copy_field_to_guest(u_domctl, domctl, u.get_device_group) )
            ret = -EFAULT;
    }
    break;

    case XEN_DOMCTL_test_assign_device:
        ret = -ENODEV;
        if ( domctl->u.assign_device.dev != XEN_DOMCTL_DEV_PCI )
            break;

        machine_sbdf = domctl->u.assign_device.u.pci.machine_sbdf;

        ret = xsm_test_assign_device(XSM_HOOK, machine_sbdf);
        if ( ret )
            break;

        seg = machine_sbdf >> 16;
        bus = PCI_BUS(machine_sbdf);
        devfn = PCI_DEVFN2(machine_sbdf);

        if ( device_assigned(seg, bus, devfn) )
        {
            printk(XENLOG_G_INFO
                   "%04x:%02x:%02x.%u already assigned, or non-existent\n",
                   seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
            ret = -EINVAL;
        }
        break;

    case XEN_DOMCTL_assign_device:
        ret = -ENODEV;
        if ( domctl->u.assign_device.dev != XEN_DOMCTL_DEV_PCI )
            break;

        if ( unlikely(d->is_dying) )
        {
            ret = -EINVAL;
            break;
        }

        machine_sbdf = domctl->u.assign_device.u.pci.machine_sbdf;

        ret = xsm_assign_device(XSM_HOOK, d, machine_sbdf);
        if ( ret )
            break;

        seg = machine_sbdf >> 16;
        bus = PCI_BUS(machine_sbdf);
        devfn = PCI_DEVFN2(machine_sbdf);
        flag = domctl->u.assign_device.flag;
        if ( flag & ~XEN_DOMCTL_DEV_RDM_RELAXED )
        {
            ret = -EINVAL;
            break;
        }

        ret = device_assigned(seg, bus, devfn) ?:
              assign_device(d, seg, bus, devfn, flag);
        if ( ret == -ERESTART )
            ret = hypercall_create_continuation(__HYPERVISOR_domctl,
                                                "h", u_domctl);
        else if ( ret )
            printk(XENLOG_G_ERR "XEN_DOMCTL_assign_device: "
                   "assign %04x:%02x:%02x.%u to dom%d failed (%d)\n",
                   seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                   d->domain_id, ret);

        break;

    case XEN_DOMCTL_deassign_device:
        ret = -ENODEV;
        if ( domctl->u.assign_device.dev != XEN_DOMCTL_DEV_PCI )
            break;

        machine_sbdf = domctl->u.assign_device.u.pci.machine_sbdf;

        ret = xsm_deassign_device(XSM_HOOK, d, machine_sbdf);
        if ( ret )
            break;

        seg = machine_sbdf >> 16;
        bus = PCI_BUS(machine_sbdf);
        devfn = PCI_DEVFN2(machine_sbdf);

        spin_lock(&pcidevs_lock);
        ret = deassign_device(d, seg, bus, devfn);
        spin_unlock(&pcidevs_lock);
        if ( ret )
            printk(XENLOG_G_ERR
                   "deassign %04x:%02x:%02x.%u from dom%d failed (%d)\n",
                   seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                   d->domain_id, ret);

        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
