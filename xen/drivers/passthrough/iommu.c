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

static void parse_iommu_param(char *s);
static int iommu_populate_page_table(struct domain *d);

/*
 * The 'iommu' parameter enables the IOMMU.  Optional comma separated
 * value may contain:
 *
 *   off|no|false|disable       Disable IOMMU (default)
 *   force|required             Don't boot unless IOMMU is enabled
 *   workaround_bios_bug        Workaround some bios issue to still enable
                                VT-d, don't guarantee security
 *   passthrough                Enable VT-d DMA passthrough (no DMA
 *                              translation for Dom0)
 *   no-snoop                   Disable VT-d Snoop Control
 *   no-qinval                  Disable VT-d Queued Invalidation
 *   no-intremap                Disable VT-d Interrupt Remapping
 */
custom_param("iommu", parse_iommu_param);
bool_t __read_mostly iommu_enabled = 1;
bool_t __read_mostly force_iommu;
bool_t __read_mostly iommu_verbose;
bool_t __read_mostly iommu_workaround_bios_bug;
bool_t __read_mostly iommu_passthrough;
bool_t __read_mostly iommu_snoop = 1;
bool_t __read_mostly iommu_qinval = 1;
bool_t __read_mostly iommu_intremap = 1;
bool_t __read_mostly amd_iommu_debug;
bool_t __read_mostly amd_iommu_perdev_intremap;

static void __init parse_iommu_param(char *s)
{
    char *ss;

    do {
        ss = strchr(s, ',');
        if ( ss )
            *ss = '\0';

        if ( !strcmp(s, "off") || !strcmp(s, "no") || !strcmp(s, "false") ||
             !strcmp(s, "0") || !strcmp(s, "disable") )
            iommu_enabled = 0;
        else if ( !strcmp(s, "force") || !strcmp(s, "required") )
            force_iommu = 1;
        else if ( !strcmp(s, "workaround_bios_bug") )
            iommu_workaround_bios_bug = 1;
        else if ( !strcmp(s, "passthrough") )
            iommu_passthrough = 1;
        else if ( !strcmp(s, "verbose") )
            iommu_verbose = 1;
        else if ( !strcmp(s, "no-snoop") )
            iommu_snoop = 0;
        else if ( !strcmp(s, "no-qinval") )
            iommu_qinval = 0;
        else if ( !strcmp(s, "no-intremap") )
            iommu_intremap = 0;
        else if ( !strcmp(s, "amd-iommu-debug") )
            amd_iommu_debug = 1;
        else if ( !strcmp(s, "amd-iommu-perdev-intremap") )
            amd_iommu_perdev_intremap = 1;

        s = ss + 1;
    } while ( ss );
}

int iommu_domain_init(struct domain *domain)
{
    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    spin_lock_init(&hd->mapping_lock);
    INIT_LIST_HEAD(&hd->g2m_ioport_list);
    INIT_LIST_HEAD(&hd->mapped_rmrrs);

    if ( !iommu_enabled )
        return 0;

    hd->platform_ops = iommu_get_ops();
    return hd->platform_ops->init(domain);
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

int assign_device(struct domain *d, u8 bus, u8 devfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    int rc = 0;

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    spin_lock(&pcidevs_lock);
    if ( (rc = hd->platform_ops->assign_device(d, bus, devfn)) )
        goto done;

    if ( has_arch_pdevs(d) && !need_iommu(d) )
    {
        d->need_iommu = 1;
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

/* caller should hold the pcidevs_lock */
int deassign_device(struct domain *d, u8 bus, u8 devfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct pci_dev *pdev = NULL;
    int ret = 0;

    if ( !iommu_enabled || !hd->platform_ops )
        return -EINVAL;

    ASSERT(spin_is_locked(&pcidevs_lock));
    pdev = pci_get_pdev(bus, devfn);
    if ( !pdev )
        return -ENODEV;

    if ( pdev->domain != d )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "d%d: deassign a device not owned\n", d->domain_id);
        return -EINVAL;
    }

    ret = hd->platform_ops->reassign_device(d, dom0, bus, devfn);
    if ( ret )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "d%d: Deassign device (%x:%x.%x) failed!\n",
                d->domain_id, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
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

    if ( iommu_enabled )
    {
        rc = iommu_hardware_setup();
        iommu_enabled = (rc == 0);
    }

    if ( force_iommu && !iommu_enabled )
        panic("IOMMU setup failed, crash Xen for security purpose!\n");

    if ( !iommu_enabled )
    {
        iommu_snoop = 0;
        iommu_qinval = 0;
        iommu_intremap = 0;
    }
    printk("I/O virtualisation %sabled\n", iommu_enabled ? "en" : "dis");
    return rc;
}

int iommu_get_device_group(struct domain *d, u8 bus, u8 devfn, 
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

    group_id = ops->get_device_group_id(bus, devfn);

    spin_lock(&pcidevs_lock);
    for_each_pdev( d, pdev )
    {
        if ( (pdev->bus == bus) && (pdev->devfn == devfn) )
            continue;

        sdev_id = ops->get_device_group_id(pdev->bus, pdev->devfn);
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
