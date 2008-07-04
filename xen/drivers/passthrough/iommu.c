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
#include <xen/paging.h>
#include <xen/guest_access.h>

extern struct iommu_ops intel_iommu_ops;
extern struct iommu_ops amd_iommu_ops;
static int iommu_populate_page_table(struct domain *d);
int intel_vtd_setup(void);
int amd_iov_detect(void);

int iommu_enabled = 1;
boolean_param("iommu", iommu_enabled);

int iommu_pv_enabled = 0;
boolean_param("iommu_pv", iommu_pv_enabled);

int iommu_domain_init(struct domain *domain)
{
    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    spin_lock_init(&hd->mapping_lock);
    INIT_LIST_HEAD(&hd->g2m_ioport_list);

    if ( !iommu_enabled )
        return 0;

    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        hd->platform_ops = &intel_iommu_ops;
        break;
    case X86_VENDOR_AMD:
        hd->platform_ops = &amd_iommu_ops;
        break;
    default:
        BUG();
    }

    return hd->platform_ops->init(domain);
}

int iommu_add_device(struct pci_dev *pdev)
{
    struct hvm_iommu *hd;
    if ( !pdev->domain )
        return -EINVAL;

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
    int rc;

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    if ( (rc = hd->platform_ops->assign_device(d, bus, devfn)) )
        return rc;

    if ( has_arch_pdevs(d) && !is_hvm_domain(d) && !need_iommu(d) )
    {
        d->need_iommu = 1;
        return iommu_populate_page_table(d);
    }
    return 0;
}

static int iommu_populate_page_table(struct domain *d)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct page_info *page;
    int rc;

    spin_lock(&d->page_alloc_lock);

    list_for_each_entry ( page, &d->page_list, list )
    {
        if ( (page->u.inuse.type_info & PGT_type_mask) == PGT_writable_page )
        {
            rc = hd->platform_ops->map_page(
                d, mfn_to_gmfn(d, page_to_mfn(page)), page_to_mfn(page));
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
    struct hvm_irq_dpci *hvm_irq_dpci = domain_get_irq_dpci(d);
    uint32_t i;
    struct hvm_iommu *hd  = domain_hvm_iommu(d);
    struct list_head *ioport_list, *digl_list, *tmp;
    struct g2m_ioport *ioport;
    struct dev_intx_gsi_link *digl;

    if ( !iommu_enabled || !hd->platform_ops )
        return;

    if ( !is_hvm_domain(d) && !need_iommu(d)  )
        return;

    if ( need_iommu(d) )
    {
        d->need_iommu = 0;
        hd->platform_ops->teardown(d);
        return;
    }

    if ( hvm_irq_dpci != NULL )
    {
        for ( i = 0; i < NR_IRQS; i++ )
        {
            if ( !(hvm_irq_dpci->mirq[i].flags & HVM_IRQ_DPCI_VALID) )
                continue;

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

    if ( hd )
    {
        list_for_each_safe ( ioport_list, tmp, &hd->g2m_ioport_list )
        {
            ioport = list_entry(ioport_list, struct g2m_ioport, list);
            list_del(&ioport->list);
            xfree(ioport);
        }
    }

    return hd->platform_ops->teardown(d);
}

int iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    return hd->platform_ops->map_page(d, gfn, mfn);
}

int iommu_unmap_page(struct domain *d, unsigned long gfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    return hd->platform_ops->unmap_page(d, gfn);
}

void deassign_device(struct domain *d, u8 bus, u8 devfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops )
        return;

    hd->platform_ops->reassign_device(d, dom0, bus, devfn);

    if ( !has_arch_pdevs(d) && need_iommu(d) )
    {
        d->need_iommu = 0;
        hd->platform_ops->teardown(d);
    }
}

static int iommu_setup(void)
{
    int rc = -ENODEV;

    if ( !iommu_enabled )
        goto out;

    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        rc = intel_vtd_setup();
        break;
    case X86_VENDOR_AMD:
        rc = amd_iov_detect();
        break;
    }

    iommu_enabled = (rc == 0);

 out:
    if ( !iommu_enabled )
        iommu_pv_enabled = 0;
    printk("I/O virtualisation %sabled\n", iommu_enabled ? "en" : "dis");
    if ( iommu_enabled )
        printk("I/O virtualisation for PV guests %sabled\n",
               iommu_pv_enabled ? "en" : "dis");
    return rc;
}
__initcall(iommu_setup);

int iommu_get_device_group(struct domain *d, u8 bus, u8 devfn, 
    XEN_GUEST_HANDLE_64(uint32) buf, int max_sdevs)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    struct pci_dev *pdev;
    int group_id, sdev_id;
    u32 bdf;
    int i = 0;
    struct iommu_ops *ops = hd->platform_ops;

    if ( !iommu_enabled || !ops || !ops->get_device_group_id )
        return 0;

    group_id = ops->get_device_group_id(bus, devfn);

    read_lock(&pcidevs_lock);
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
                read_unlock(&pcidevs_lock);
                return -1;
            }
            i++;
        }
    }
    read_unlock(&pcidevs_lock);

    return i;
}
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
