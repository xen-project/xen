/*
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
#include <xen/iommu.h>
#include <asm/hvm/iommu.h>
#include <xen/paging.h>
#include <xen/guest_access.h>
#include <xen/softirq.h>
#include <xen/keyhandler.h>
#include <xsm/xsm.h>

static void parse_iommu_param(char *s);
static int iommu_populate_page_table(struct domain *d);
static void iommu_dump_p2m_table(unsigned char key);

/*
 * The 'iommu' parameter enables the IOMMU.  Optional comma separated
 * value may contain:
 *
 *   off|no|false|disable       Disable IOMMU (default)
 *   force|required             Don't boot unless IOMMU is enabled
 *   workaround_bios_bug        Workaround some bios issue to still enable
                                VT-d, don't guarantee security
 *   dom0-passthrough           No DMA translation at all for Dom0
 *   dom0-strict                No 1:1 memory mapping for Dom0
 *   no-snoop                   Disable VT-d Snoop Control
 *   no-qinval                  Disable VT-d Queued Invalidation
 *   no-intremap                Disable VT-d Interrupt Remapping
 */
custom_param("iommu", parse_iommu_param);
bool_t __read_mostly iommu_enabled = 1;
bool_t __read_mostly force_iommu;
bool_t __initdata iommu_dom0_strict;
bool_t __read_mostly iommu_verbose;
bool_t __read_mostly iommu_workaround_bios_bug;
bool_t __read_mostly iommu_passthrough;
bool_t __read_mostly iommu_snoop = 1;
bool_t __read_mostly iommu_qinval = 1;
bool_t __read_mostly iommu_intremap = 1;
bool_t __read_mostly iommu_hap_pt_share = 1;
bool_t __read_mostly iommu_debug;
bool_t __read_mostly amd_iommu_perdev_intremap;

DEFINE_PER_CPU(bool_t, iommu_dont_flush_iotlb);

static struct keyhandler iommu_p2m_table = {
    .diagnostic = 0,
    .u.fn = iommu_dump_p2m_table,
    .desc = "dump iommu p2m table"
};

static void __init parse_iommu_param(char *s)
{
    char *ss;
    int val;

    do {
        val = !!strncmp(s, "no-", 3);
        if ( !val )
            s += 3;

        ss = strchr(s, ',');
        if ( ss )
            *ss = '\0';

        if ( !parse_bool(s) )
            iommu_enabled = 0;
        else if ( !strcmp(s, "force") || !strcmp(s, "required") )
            force_iommu = val;
        else if ( !strcmp(s, "workaround_bios_bug") )
            iommu_workaround_bios_bug = val;
        else if ( !strcmp(s, "verbose") )
            iommu_verbose = val;
        else if ( !strcmp(s, "snoop") )
            iommu_snoop = val;
        else if ( !strcmp(s, "qinval") )
            iommu_qinval = val;
        else if ( !strcmp(s, "intremap") )
            iommu_intremap = val;
        else if ( !strcmp(s, "debug") )
            iommu_debug = val;
        else if ( !strcmp(s, "amd-iommu-perdev-intremap") )
            amd_iommu_perdev_intremap = val;
        else if ( !strcmp(s, "dom0-passthrough") )
            iommu_passthrough = val;
        else if ( !strcmp(s, "dom0-strict") )
            iommu_dom0_strict = val;
        else if ( !strcmp(s, "sharept") )
            iommu_hap_pt_share = val;

        s = ss + 1;
    } while ( ss );
}

int iommu_domain_init(struct domain *d)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    spin_lock_init(&hd->mapping_lock);
    INIT_LIST_HEAD(&hd->g2m_ioport_list);
    INIT_LIST_HEAD(&hd->mapped_rmrrs);

    if ( !iommu_enabled )
        return 0;

    hd->platform_ops = iommu_get_ops();
    return hd->platform_ops->init(d);
}

void __init iommu_dom0_init(struct domain *d)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled )
        return;

    register_keyhandler('o', &iommu_p2m_table);
    d->need_iommu = !!iommu_dom0_strict;
    if ( need_iommu(d) )
    {
        struct page_info *page;
        unsigned int i = 0;
        page_list_for_each ( page, &d->page_list )
        {
            unsigned long mfn = page_to_mfn(page);
            unsigned int mapping = IOMMUF_readable;
            if ( ((page->u.inuse.type_info & PGT_count_mask) == 0) ||
                 ((page->u.inuse.type_info & PGT_type_mask)
                  == PGT_writable_page) )
                mapping |= IOMMUF_writable;
            hd->platform_ops->map_page(d, mfn, mfn, mapping);
            if ( !(i++ & 0xfffff) )
                process_pending_softirqs();
        }
    }

    return hd->platform_ops->dom0_init(d);
}

int iommu_add_device(struct pci_dev *pdev)
{
    struct hvm_iommu *hd;

    if ( !pdev->domain )
        return -EINVAL;

    ASSERT(spin_is_locked(&pcidevs_lock));

    hd = domain_hvm_iommu(pdev->domain);
    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    return hd->platform_ops->add_device(pdev);
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

    return hd->platform_ops->enable_device(pdev);
}

int iommu_remove_device(struct pci_dev *pdev)
{
    struct hvm_iommu *hd;
    if ( !pdev->domain )
        return -EINVAL;

    hd = domain_hvm_iommu(pdev->domain);
    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    return hd->platform_ops->remove_device(pdev);
}

/*
 * If the device isn't owned by dom0, it means it already
 * has been assigned to other domain, or it doesn't exist.
 */
static int device_assigned(u16 seg, u8 bus, u8 devfn)
{
    struct pci_dev *pdev;

    spin_lock(&pcidevs_lock);
    pdev = pci_get_pdev_by_domain(dom0, seg, bus, devfn);
    spin_unlock(&pcidevs_lock);

    return pdev ? 0 : -1;
}

static int assign_device(struct domain *d, u16 seg, u8 bus, u8 devfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    int rc = 0;

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    /* Prevent device assign if mem paging or mem sharing have been 
     * enabled for this domain */
    if ( unlikely(!need_iommu(d) &&
            (d->arch.hvm_domain.mem_sharing_enabled ||
             d->mem_event->paging.ring_page)) )
        return -EXDEV;

    spin_lock(&pcidevs_lock);
    if ( (rc = hd->platform_ops->assign_device(d, seg, bus, devfn)) )
        goto done;

    if ( has_arch_pdevs(d) && !need_iommu(d) )
    {
        d->need_iommu = 1;
        if ( !iommu_use_hap_pt(d) )
            rc = iommu_populate_page_table(d);
        goto done;
    }
done:
    spin_unlock(&pcidevs_lock);
    return rc;
}

static int iommu_populate_page_table(struct domain *d)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct page_info *page;
    int rc;

    spin_lock(&d->page_alloc_lock);

    this_cpu(iommu_dont_flush_iotlb) = 1;
    page_list_for_each ( page, &d->page_list )
    {
        if ( is_hvm_domain(d) ||
            (page->u.inuse.type_info & PGT_type_mask) == PGT_writable_page )
        {
            BUG_ON(SHARED_M2P(mfn_to_gmfn(d, page_to_mfn(page))));
            rc = hd->platform_ops->map_page(
                d, mfn_to_gmfn(d, page_to_mfn(page)), page_to_mfn(page),
                IOMMUF_readable|IOMMUF_writable);
            if (rc)
            {
                spin_unlock(&d->page_alloc_lock);
                hd->platform_ops->teardown(d);
                return rc;
            }
        }
    }
    this_cpu(iommu_dont_flush_iotlb) = 0;
    iommu_iotlb_flush_all(d);
    spin_unlock(&d->page_alloc_lock);
    return 0;
}


void iommu_domain_destroy(struct domain *d)
{
    struct hvm_iommu *hd  = domain_hvm_iommu(d);
    struct list_head *ioport_list, *rmrr_list, *tmp;
    struct g2m_ioport *ioport;
    struct mapped_rmrr *mrmrr;

    if ( !iommu_enabled || !hd->platform_ops )
        return;

    if ( need_iommu(d) )
    {
        d->need_iommu = 0;
        hd->platform_ops->teardown(d);
    }

    list_for_each_safe ( ioport_list, tmp, &hd->g2m_ioport_list )
    {
        ioport = list_entry(ioport_list, struct g2m_ioport, list);
        list_del(&ioport->list);
        xfree(ioport);
    }

    list_for_each_safe ( rmrr_list, tmp, &hd->mapped_rmrrs )
    {
        mrmrr = list_entry(rmrr_list, struct mapped_rmrr, list);
        list_del(&mrmrr->list);
        xfree(mrmrr);
    }
}

int iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn,
                   unsigned int flags)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    return hd->platform_ops->map_page(d, gfn, mfn, flags);
}

int iommu_unmap_page(struct domain *d, unsigned long gfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    return hd->platform_ops->unmap_page(d, gfn);
}

void iommu_iotlb_flush(struct domain *d, unsigned long gfn, unsigned int page_count)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops || !hd->platform_ops->iotlb_flush )
        return;

    hd->platform_ops->iotlb_flush(d, gfn, page_count);
}

void iommu_iotlb_flush_all(struct domain *d)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops || !hd->platform_ops->iotlb_flush_all )
        return;

    hd->platform_ops->iotlb_flush_all(d);
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
    pdev = pci_get_pdev(seg, bus, devfn);
    if ( !pdev )
        return -ENODEV;

    if ( pdev->domain != d )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "d%d: deassign a device not owned\n", d->domain_id);
        return -EINVAL;
    }

    ret = hd->platform_ops->reassign_device(d, dom0, seg, bus, devfn);
    if ( ret )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "d%d: Deassign device (%04x:%02x:%02x.%u) failed!\n",
                d->domain_id, seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
        return ret;
    }

    if ( !has_arch_pdevs(d) && need_iommu(d) )
    {
        d->need_iommu = 0;
        hd->platform_ops->teardown(d);
    }

    return ret;
}

int __init iommu_setup(void)
{
    int rc = -ENODEV;
    bool_t force_intremap = force_iommu && iommu_intremap;

    if ( iommu_dom0_strict )
        iommu_passthrough = 0;

    if ( iommu_enabled )
    {
        rc = iommu_hardware_setup();
        iommu_enabled = (rc == 0);
    }

    if ( (force_iommu && !iommu_enabled) ||
         (force_intremap && !iommu_intremap) )
        panic("Couldn't enable %s and iommu=required/force\n",
              !iommu_enabled ? "IOMMU" : "Interrupt Remapping");

    if ( !iommu_enabled )
    {
        iommu_snoop = 0;
        iommu_qinval = 0;
        iommu_intremap = 0;
        iommu_passthrough = 0;
        iommu_dom0_strict = 0;
    }
    printk("I/O virtualisation %sabled\n", iommu_enabled ? "en" : "dis");
    if ( iommu_enabled )
        printk(" - Dom0 mode: %s\n",
               iommu_passthrough ? "Passthrough" :
               iommu_dom0_strict ? "Strict" : "Relaxed");

    return rc;
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

        if ( xsm_get_device_group((seg << 16) | (pdev->bus << 8) | pdev->devfn) )
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

void iommu_update_ire_from_apic(
    unsigned int apic, unsigned int reg, unsigned int value)
{
    const struct iommu_ops *ops = iommu_get_ops();
    ops->update_ire_from_apic(apic, reg, value);
}
void iommu_update_ire_from_msi(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    const struct iommu_ops *ops = iommu_get_ops();
    ops->update_ire_from_msi(msi_desc, msg);
}

void iommu_read_msi_from_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    const struct iommu_ops *ops = iommu_get_ops();
    ops->read_msi_from_ire(msi_desc, msg);
}

unsigned int iommu_read_apic_from_ire(unsigned int apic, unsigned int reg)
{
    const struct iommu_ops *ops = iommu_get_ops();
    return ops->read_apic_from_ire(apic, reg);
}

void iommu_resume()
{
    const struct iommu_ops *ops = iommu_get_ops();
    if ( iommu_enabled )
        ops->resume();
}

void iommu_suspend()
{
    const struct iommu_ops *ops = iommu_get_ops();
    if ( iommu_enabled )
        ops->suspend();
}

void iommu_share_p2m_table(struct domain* d)
{
    const struct iommu_ops *ops = iommu_get_ops();

    if ( iommu_enabled && is_hvm_domain(d) )
        ops->share_p2m(d);
}

void iommu_crash_shutdown(void)
{
    const struct iommu_ops *ops = iommu_get_ops();
    if ( iommu_enabled )
        ops->crash_shutdown();
    iommu_enabled = 0;
}

int iommu_do_domctl(
    struct xen_domctl *domctl,
    XEN_GUEST_HANDLE(xen_domctl_t) u_domctl)
{
    struct domain *d;
    u16 seg;
    u8 bus, devfn;
    int ret = 0;

    if ( !iommu_enabled )
        return -ENOSYS;

    switch ( domctl->cmd )
    {
    case XEN_DOMCTL_get_device_group:
    {
        u32 max_sdevs;
        XEN_GUEST_HANDLE_64(uint32) sdevs;

        ret = xsm_get_device_group(domctl->u.get_device_group.machine_sbdf);
        if ( ret )
            break;

        ret = -EINVAL;
        if ( (d = rcu_lock_domain_by_id(domctl->domain)) == NULL )
            break;

        seg = domctl->u.get_device_group.machine_sbdf >> 16;
        bus = (domctl->u.get_device_group.machine_sbdf >> 8) & 0xff;
        devfn = domctl->u.get_device_group.machine_sbdf & 0xff;
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
        if ( copy_to_guest(u_domctl, domctl, 1) )
            ret = -EFAULT;
        rcu_unlock_domain(d);
    }
    break;

    case XEN_DOMCTL_test_assign_device:
        ret = xsm_test_assign_device(domctl->u.assign_device.machine_sbdf);
        if ( ret )
            break;

        seg = domctl->u.get_device_group.machine_sbdf >> 16;
        bus = (domctl->u.assign_device.machine_sbdf >> 8) & 0xff;
        devfn = domctl->u.assign_device.machine_sbdf & 0xff;

        if ( device_assigned(seg, bus, devfn) )
        {
            printk(XENLOG_G_INFO
                   "%04x:%02x:%02x.%u already assigned, or non-existent\n",
                   seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
            ret = -EINVAL;
        }
        break;

    case XEN_DOMCTL_assign_device:
        if ( unlikely((d = get_domain_by_id(domctl->domain)) == NULL) ||
             unlikely(d->is_dying) )
        {
            printk(XENLOG_G_ERR
                   "XEN_DOMCTL_assign_device: get_domain_by_id() failed\n");
            ret = -EINVAL;
            if ( d )
                goto assign_device_out;
            break;
        }

        ret = xsm_assign_device(d, domctl->u.assign_device.machine_sbdf);
        if ( ret )
            goto assign_device_out;

        seg = domctl->u.get_device_group.machine_sbdf >> 16;
        bus = (domctl->u.assign_device.machine_sbdf >> 8) & 0xff;
        devfn = domctl->u.assign_device.machine_sbdf & 0xff;

        ret = assign_device(d, seg, bus, devfn);
        if ( ret )
            printk(XENLOG_G_ERR "XEN_DOMCTL_assign_device: "
                   "assign %04x:%02x:%02x.%u to dom%d failed (%d)\n",
                   seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                   d->domain_id, ret);

    assign_device_out:
        put_domain(d);
        break;

    case XEN_DOMCTL_deassign_device:
        if ( unlikely((d = get_domain_by_id(domctl->domain)) == NULL) )
        {
            printk(XENLOG_G_ERR
                   "XEN_DOMCTL_deassign_device: get_domain_by_id() failed\n");
            ret = -EINVAL;
            break;
        }

        ret = xsm_deassign_device(d, domctl->u.assign_device.machine_sbdf);
        if ( ret )
            goto deassign_device_out;

        seg = domctl->u.get_device_group.machine_sbdf >> 16;
        bus = (domctl->u.assign_device.machine_sbdf >> 8) & 0xff;
        devfn = domctl->u.assign_device.machine_sbdf & 0xff;

        spin_lock(&pcidevs_lock);
        ret = deassign_device(d, seg, bus, devfn);
        spin_unlock(&pcidevs_lock);
        if ( ret )
            printk(XENLOG_G_ERR
                   "deassign %04x:%02x:%02x.%u from dom%d failed (%d)\n",
                   seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                   d->domain_id, ret);

    deassign_device_out:
        put_domain(d);
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

static void iommu_dump_p2m_table(unsigned char key)
{
    struct domain *d;
    const struct iommu_ops *ops;

    if ( !iommu_enabled )
    {
        printk("IOMMU not enabled!\n");
        return;
    }

    ops = iommu_get_ops();
    for_each_domain(d)
    {
        if ( !d->domain_id )
            continue;

        if ( iommu_use_hap_pt(d) )
        {
            printk("\ndomain%d IOMMU p2m table shared with MMU: \n", d->domain_id);
            continue;
        }

        printk("\ndomain%d IOMMU p2m table: \n", d->domain_id);
        ops->dump_p2m_table(d);
    }
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
